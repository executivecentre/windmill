package httpserver

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizeRD(t *testing.T) {
	cases := map[string]string{
		"":                                  "/",
		"/":                                 "/",
		"/scripts?x=1#frag":                 "/scripts?x=1#frag",
		"/a/b%2Fc":                          "/a/b%2Fc",
		"//evil.example":                    "/",
		"/\\evil.example":                   "/",
		"\\\\evil.example":                  "/",
		"https://evil.example":              "/",
		"HTTPS://evil.example":              "/",
		"javascript:alert(1)":               "/",
		"evil.example/x":                    "/",
		"/\t/evil.example":                  "/",
		"/\n/evil.example":                  "/",
		"/\r\nLocation: x":                  "/",
		"/ok\x00":                           "/",
		"/ /evil":                           "/",
		"/a\\b":                             "/",
		"/" + strings.Repeat("a", maxRDLen): "/",
	}
	for in, want := range cases {
		if got := sanitizeRD(in); got != want {
			t.Errorf("sanitizeRD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlowCookieSealing(t *testing.T) {
	s, err := newSealer([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	f := flow{State: "state-value", Nonce: "n", Verifier: "v", RD: "/x", Expires: now.Add(flowTTL).Unix()}
	sealed, err := s.seal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "state-value") {
		t.Fatal("cookie is not encrypted")
	}
	got, err := s.open(sealed, now)
	if err != nil || got != f {
		t.Fatalf("round trip %+v %v", got, err)
	}
	if _, err := s.open(sealed, now.Add(flowTTL+time.Second)); err == nil {
		t.Fatal("expired cookie accepted")
	}
	b := []byte(sealed)
	b[len(b)/2] ^= 1
	if _, err := s.open(string(b), now); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	other, _ := newSealer([]byte(strings.Repeat("j", 32)))
	if _, err := other.open(sealed, now); err == nil {
		t.Fatal("cookie opened with another key")
	}
}

func TestReplayGuard(t *testing.T) {
	g := newReplayGuard()
	now := time.Unix(1_800_000_000, 0)
	exp := now.Add(time.Minute)
	if !g.consume("a", exp, now) || g.consume("a", exp, now) {
		t.Fatal("state consumed twice")
	}
	if !g.consume("b", exp, now) {
		t.Fatal("distinct state refused")
	}
	g.consume("c", exp, now.Add(2*time.Minute)) // prunes a and b
	if len(g.used) != 1 {
		t.Fatalf("expired states not pruned: %d", len(g.used))
	}
}
