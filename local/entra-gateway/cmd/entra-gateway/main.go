// Command entra-gateway signs users in to Windmill with Microsoft Entra ID. With a group
// mapping file it also keeps their Windmill accounts, workspace memberships and groups in line
// with Entra group membership; without one it works like Windmill's own Microsoft SSO.
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

const (
	shutdownTimeout = 20 * time.Second
	appRetry        = 30 * time.Second // while Windmill's app registration is missing or rejected
	appWatch        = time.Minute      // for changes to it once loaded
)

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

	wm := windmill.New(cfg.WindmillURL, cfg.SuperadminSecret, nil)
	var appFP string
	if cfg.EntraFromWindmill {
		appFP, err = waitForApp(ctx, log, wm, cfg, checkClientSecret(&http.Client{Timeout: 10 * time.Second}), appRetry)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	openAccess := cfg.Mappings == nil
	var scopes []string
	if openAccess {
		scopes = []string{"User.Read"}
	}
	auth := oidc.New(oidc.Settings{
		Issuer:       cfg.Issuer(),
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL(),
		ExtraScopes:  scopes,
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
	engine := sync.New(sync.Settings{
		Mappings:      cfg.Mappings,
		DomainAllowed: cfg.DomainAllowed,
		AdoptExisting: cfg.AdoptExisting,
		OpenAccess:    openAccess,
	}, g, wm, st, log)
	// Open access manages no memberships and reads no directory with app permissions.
	if !openAccess {
		go engine.RunReconciler(ctx, cfg.ReconcileInterval)
	}
	if cfg.EntraFromWindmill {
		go watchApp(ctx, log, wm, appFP, appWatch, stop)
	}

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
		"mappings", len(cfg.Mappings), "open_access", openAccess, "entra_from_windmill", cfg.EntraFromWindmill,
		"reconcile_interval", cfg.ReconcileInterval.String())

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
