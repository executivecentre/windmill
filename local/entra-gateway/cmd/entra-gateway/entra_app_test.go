package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"entra-gateway/internal/config"
	"entra-gateway/internal/windmill"
)

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type fakeSource struct {
	mu  gosync.Mutex
	app *windmill.MicrosoftApp
}

func (f *fakeSource) MicrosoftApp(context.Context) (*windmill.MicrosoftApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.app == nil {
		return nil, nil
	}
	a := *f.app
	return &a, nil
}

func (f *fakeSource) set(app *windmill.MicrosoftApp) {
	f.mu.Lock()
	f.app = app
	f.mu.Unlock()
}

func accept(context.Context, *config.Config) error { return nil }

func TestLoadApp(t *testing.T) {
	ctx := context.Background()
	good := &windmill.MicrosoftApp{Key: "ms_teams", TenantID: tenant, ClientID: client, Secret: "the-secret-value"}
	reject := func(context.Context, *config.Config) error { return errors.New("Entra rejected") }

	cases := map[string]struct {
		app   *windmill.MicrosoftApp
		check secretCheck
		want  string
	}{
		"no entry":   {nil, accept, "no Microsoft entry"},
		"bad tenant": {&windmill.MicrosoftApp{Key: "ms_teams", TenantID: "contoso", ClientID: client, Secret: "s"}, accept, "oauths.ms_teams: tenant"},
		"rejected":   {good, reject, "oauths.ms_teams: Entra rejected"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadApp(ctx, &fakeSource{app: c.app}, &config.Config{}, c.check)
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "the-secret-value") {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}

	cfg := &config.Config{}
	fp, err := loadApp(ctx, &fakeSource{app: good}, cfg, accept)
	if err != nil || cfg.TenantID != tenant || cfg.ClientID != client || cfg.ClientSecret != "the-secret-value" {
		t.Fatalf("load: %v", err)
	}
	rotated := *good
	rotated.Secret = "rotated"
	if fp != fingerprint(good) || fp == fingerprint(&rotated) {
		t.Fatal("fingerprint does not follow the secret")
	}
}

// AADSTS7000215 is what Entra answers when the Secret ID was saved instead of the Value.
func TestCheckClientSecret(t *testing.T) {
	var answer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if answer == "" {
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	cfg := &config.Config{AuthorityURL: srv.URL, GraphURL: "https://graph.example", TenantID: tenant,
		ClientID: client, ClientSecret: "the-secret-value"}
	check := checkClientSecret(srv.Client())

	if err := check(context.Background(), cfg); err != nil {
		t.Fatalf("accepted secret: %v", err)
	}
	answer = `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`
	if err := check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "not its Secret ID") {
		t.Fatalf("secret ID hint: %v", err)
	}
	answer = `{"error":"unauthorized_client","error_description":"AADSTS700016: Application not found."}`
	err := check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "unauthorized_client AADSTS700016") || strings.Contains(err.Error(), "the-secret-value") {
		t.Fatalf("other rejection: %v", err)
	}
}

func TestWaitThenWatchApp(t *testing.T) {
	var logs bytes.Buffer
	var logMu gosync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&logs, &logMu}, nil))
	logged := func() string { logMu.Lock(); defer logMu.Unlock(); return logs.String() }
	src := &fakeSource{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		time.Sleep(30 * time.Millisecond)
		src.set(&windmill.MicrosoftApp{Key: "ms_teams", TenantID: tenant, ClientID: client, Secret: "secret-v1"})
	}()
	cfg := &config.Config{}
	fp, err := waitForApp(ctx, log, src, cfg, accept, 10*time.Millisecond)
	if err != nil || cfg.ClientSecret != "secret-v1" {
		t.Fatalf("wait: %v", err)
	}
	if !strings.Contains(logged(), "no Microsoft entry") {
		t.Fatalf("waiting was not logged: %s", logged())
	}

	done := make(chan struct{})
	go watchApp(ctx, log, src, fp, 10*time.Millisecond, func() { close(done) })
	time.Sleep(40 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("unchanged registration reported as changed")
	default:
	}
	src.set(&windmill.MicrosoftApp{Key: "ms_teams", TenantID: tenant, ClientID: client, Secret: "secret-v2"})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("secret change not noticed")
	}
	if strings.Contains(logged(), "secret-v") {
		t.Fatal("a secret reached the log")
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *gosync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
