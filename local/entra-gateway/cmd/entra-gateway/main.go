// Command entra-gateway signs users in to Windmill with Microsoft Entra ID and keeps their
// Windmill accounts, workspace memberships and groups in line with Entra group membership.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"entra-gateway/internal/config"
	"entra-gateway/internal/graph"
	"entra-gateway/internal/httpserver"
	"entra-gateway/internal/oidc"
	"entra-gateway/internal/store"
	"entra-gateway/internal/sync"
	"entra-gateway/internal/windmill"
	"entra-gateway/migrations"
)

const shutdownTimeout = 20 * time.Second

func main() {
	// The runtime image has no shell or curl, so the container healthcheck runs the binary itself.
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("entra-gateway stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(config.OSEnv())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx, migrations.FS); err != nil {
		return err
	}

	auth := oidc.New(oidc.Settings{
		Issuer:       cfg.Issuer(),
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL(),
	})
	go auth.RunDiscovery(ctx, func(err error) { log.Warn("oidc discovery failed; retrying", "err", err) })

	g, err := graph.New(graph.Settings{
		BaseURL:      cfg.GraphURL,
		TokenURL:     cfg.TokenURL(),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
	})
	if err != nil {
		return err
	}
	wm := windmill.New(cfg.WindmillURL, cfg.SuperadminSecret, nil)
	engine := sync.New(sync.Settings{
		Mappings:      cfg.Mappings,
		DomainAllowed: cfg.DomainAllowed,
		AdoptExisting: cfg.AdoptExisting,
	}, g, wm, st, log)
	go engine.RunReconciler(ctx, cfg.ReconcileInterval)

	srv, err := httpserver.New(httpserver.Settings{
		PublicBaseURL: cfg.PublicBaseURL,
		CookieKey:     cfg.CookieKey,
		LoginLinkTTL:  cfg.LoginLinkTTL,
	}, auth, engine, wm, st, log)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.ListenAndServe() }()
	log.Info("entra-gateway listening", "addr", cfg.ListenAddr, "public_base_url", cfg.PublicBaseURL.String(),
		"mappings", len(cfg.Mappings), "reconcile_interval", cfg.ReconcileInterval.String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("entra-gateway shut down")
	return nil
}

func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/readyz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
