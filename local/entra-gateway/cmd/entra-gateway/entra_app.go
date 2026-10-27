package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"entra-gateway/internal/config"
	"entra-gateway/internal/windmill"
)

// appSource is where the Entra app registration is kept when no ENTRA_* values are set.
type appSource interface {
	MicrosoftApp(ctx context.Context) (*windmill.MicrosoftApp, error)
}

// secretCheck asks Entra whether the configured client ID and secret are accepted.
type secretCheck func(ctx context.Context, cfg *config.Config) error

var aadstsCode = regexp.MustCompile(`AADSTS\d+`)

// checkClientSecret requests a client-credentials token. That needs no API permission, so it
// only fails on a wrong tenant, client ID or secret.
func checkClientSecret(httpClient *http.Client) secretCheck {
	return func(ctx context.Context, cfg *config.Config) error {
		cc := clientcredentials.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			TokenURL:     cfg.TokenURL(),
			Scopes:       []string{cfg.GraphURL + "/.default"},
			AuthStyle:    oauth2.AuthStyleInParams,
		}
		_, err := cc.Token(context.WithValue(ctx, oauth2.HTTPClient, httpClient))
		if err == nil {
			return nil
		}
		var re *oauth2.RetrieveError
		if !errors.As(err, &re) {
			return errors.New("Entra token endpoint unreachable")
		}
		code := aadstsCode.FindString(re.ErrorDescription)
		if code == "AADSTS7000215" {
			return errors.New("Entra rejected the client secret (AADSTS7000215): save the secret's Value, not its Secret ID")
		}
		return fmt.Errorf("Entra rejected the app registration (%s %s)", re.ErrorCode, code)
	}
}

// loadApp installs Windmill's Microsoft app registration into cfg once Entra accepts it, and
// returns a fingerprint to notice later changes. The fingerprint is never logged.
func loadApp(ctx context.Context, src appSource, cfg *config.Config, check secretCheck) (string, error) {
	app, err := src.MicrosoftApp(ctx)
	if err != nil {
		return "", err
	}
	if app == nil {
		return "", errors.New("Windmill's OAuth settings have no Microsoft entry (microsoft or ms_teams)")
	}
	if err := cfg.SetEntra(app.TenantID, app.ClientID, app.Secret); err != nil {
		return "", fmt.Errorf("oauths.%s: %w", app.Key, err)
	}
	if err := check(ctx, cfg); err != nil {
		return "", fmt.Errorf("oauths.%s: %w", app.Key, err)
	}
	return fingerprint(app), nil
}

func fingerprint(app *windmill.MicrosoftApp) string {
	sum := sha256.Sum256([]byte(app.Key + "\x00" + app.TenantID + "\x00" + app.ClientID + "\x00" + app.Secret))
	return hex.EncodeToString(sum[:])
}

// waitForApp retries loadApp until it succeeds or ctx ends. Microsoft sign-in stays off (the
// gateway does not listen yet) and each failure is logged with its reason.
func waitForApp(ctx context.Context, log *slog.Logger, src appSource, cfg *config.Config, check secretCheck, every time.Duration) (string, error) {
	for {
		fp, err := loadApp(ctx, src, cfg, check)
		if err == nil {
			return fp, nil
		}
		log.Warn("Microsoft sign-in is off until Windmill's OAuth settings hold a working app registration", "reason", err.Error())
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(every):
		}
	}
}

// watchApp calls changed once Windmill's app registration differs from fp. The gateway then
// exits and its restart policy brings it back with the new registration.
func watchApp(ctx context.Context, log *slog.Logger, src appSource, fp string, every time.Duration, changed func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		app, err := src.MicrosoftApp(ctx)
		if err != nil {
			log.Warn("reading Windmill's OAuth settings failed", "err", err)
			continue
		}
		if app == nil || fingerprint(app) != fp {
			log.Info("Microsoft app registration changed in Windmill's OAuth settings; restarting to apply it")
			changed()
			return
		}
	}
}
