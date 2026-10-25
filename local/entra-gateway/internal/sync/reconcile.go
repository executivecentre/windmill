package sync

import (
	"context"
	"errors"
	gosync "sync"
	"time"

	"entra-gateway/internal/graph"
	"entra-gateway/internal/oidc"
	"entra-gateway/internal/store"
)

const reconcileConcurrency = 4

// CycleResult summarises one reconcile pass.
type CycleResult struct {
	Identities int
	Failed     int
}

// ReconcileOnce re-evaluates every linked identity against Entra. A transient Graph error
// skips that identity for this cycle (it keeps its current access) and counts as a failure;
// Graph reporting the user gone or disabled disables the Windmill account.
func (e *Engine) ReconcileOnce(ctx context.Context) (CycleResult, error) {
	idents, err := e.store.ListIdentities(ctx)
	if err != nil {
		return CycleResult{}, err
	}
	res := CycleResult{Identities: len(idents)}
	var mu gosync.Mutex
	var wg gosync.WaitGroup
	sem := make(chan struct{}, reconcileConcurrency)
	for _, ident := range idents {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ident store.Identity) {
			defer func() { <-sem; wg.Done() }()
			if err := e.reconcileIdentity(ctx, ident); err != nil {
				mu.Lock()
				res.Failed++
				mu.Unlock()
				e.log.Warn("reconcile failed", "oid", ident.ObjectID, "err", err)
			}
		}(ident)
	}
	wg.Wait()
	return res, ctx.Err()
}

func (e *Engine) reconcileIdentity(ctx context.Context, ident store.Identity) error {
	user, groups, err := e.graph.Lookup(ctx, ident.ObjectID)
	if err != nil && !errors.Is(err, graph.ErrNotFound) {
		return err
	}
	id := oidc.Identity{TenantID: ident.TenantID, ObjectID: ident.ObjectID}
	_, err = e.syncIdentity(ctx, id, user, groups, false)
	var d *DenyError
	if errors.As(err, &d) {
		return nil // the refusal has been applied (account or memberships disabled)
	}
	return err
}

// RunReconciler reconciles every interval until ctx ends, logging cycles that failed and how
// many failed in a row.
func (e *Engine) RunReconciler(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	consecutive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		start := time.Now()
		res, err := e.ReconcileOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil || res.Failed > 0 {
			consecutive++
			e.log.Warn("reconcile cycle had failures", "identities", res.Identities, "failed", res.Failed,
				"consecutive_failed_cycles", consecutive, "err", err)
			continue
		}
		consecutive = 0
		e.log.Info("reconcile cycle done", "identities", res.Identities, "duration", time.Since(start).String())
	}
}
