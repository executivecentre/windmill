package gatewaytest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"entra-gateway/internal/graph"
)

func newGraphClient(t *testing.T, p *idp, base string) *graph.Client {
	c, err := graph.New(graph.Settings{BaseURL: base, TokenURL: p.tokenURL(), ClientID: p.clientID,
		ClientSecret: p.clientSecret, HTTPClient: p.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGraphLookup(t *testing.T) {
	sec := &secrets{}
	p := newIDP(t, sec)
	g := newGraph(t, p)
	c := newGraphClient(t, p, g.srv.URL)
	ctx := context.Background()

	g.setUser(graphUser{ID: oid(1), AccountEnabled: true, UPN: "U@corp.example"}, "A", "B", "C", "D", "E")
	g.setPageSize(2)
	user, groups, err := c.Lookup(ctx, oid(1))
	if err != nil {
		t.Fatal(err)
	}
	if user.Email() != "u@corp.example" || strings.Join(groups, ",") != "a,b,c,d,e" {
		t.Fatalf("user %+v groups %v", user, groups)
	}

	if _, _, err := c.Lookup(ctx, oid(2)); !errors.Is(err, graph.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	g.setThrottle(5) // more 429s than the client retries
	if _, _, err := c.Lookup(ctx, oid(1)); err == nil {
		t.Fatal("persistent throttling did not fail the lookup")
	}
	g.setThrottle(0)

	g.setFail(true)
	_, _, err = c.Lookup(ctx, oid(1))
	if err == nil {
		t.Fatal("Graph 500 did not fail the lookup")
	}
	for _, s := range sec.all() {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error text carries a credential")
		}
	}
}

// A nextLink to another host must not receive the Graph bearer token.
func TestGraphRefusesForeignNextLink(t *testing.T) {
	sec := &secrets{}
	p := newIDP(t, sec)
	leaked := make(chan string, 1)
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"value": []any{}})
	}))
	defer foreign.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.0/users/{oid}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, graphUser{ID: r.PathValue("oid"), AccountEnabled: true, UPN: "x@corp.example"})
	})
	mux.HandleFunc("GET /v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"value": []any{}, "@odata.nextLink": foreign.URL + "/v1.0/next"})
	})
	g := httptest.NewTLSServer(mux)
	defer g.Close()

	if _, _, err := newGraphClient(t, p, g.URL).Lookup(context.Background(), oid(1)); err == nil {
		t.Fatal("foreign nextLink followed")
	}
	select {
	case <-leaked:
		t.Fatal("bearer token sent to a foreign host")
	default:
	}
}
