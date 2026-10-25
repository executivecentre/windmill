package httpserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	gosync "sync"
	"time"
	"unicode"
)

const (
	flowCookie = "__Host-wm_sso"
	flowTTL    = 10 * time.Minute
	maxRDLen   = 2048
)

// flow is the per-attempt state bound to the browser through an encrypted cookie: the
// callback must present both the cookie and a matching `state`.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	RD       string `json:"r"`
	Expires  int64  `json:"e"`
}

var errBadFlow = errors.New("flow cookie invalid or expired")

type sealer struct{ aead cipher.AEAD }

func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(f flow) (string, error) {
	plain, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, []byte(flowCookie))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (s *sealer) open(v string, now time.Time) (flow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return flow{}, errBadFlow
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(flowCookie))
	if err != nil {
		return flow{}, errBadFlow
	}
	var f flow
	if err := json.Unmarshal(plain, &f); err != nil || f.State == "" || now.Unix() > f.Expires {
		return flow{}, errBadFlow
	}
	return f, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sanitizeRD returns rd when it is a same-origin absolute path, else "/". Backslashes and
// control characters are refused because browsers turn `/\host` and `/\t/host` into `//host`.
func sanitizeRD(rd string) string {
	if rd == "" || len(rd) > maxRDLen || rd[0] != '/' {
		return "/"
	}
	if len(rd) > 1 && (rd[1] == '/' || rd[1] == '\\') {
		return "/"
	}
	for _, r := range rd {
		if r == '\\' || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "/"
		}
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return rd
}

// replayGuard remembers consumed flow states until they would have expired anyway, so a
// copied cookie and callback URL cannot be used a second time.
type replayGuard struct {
	mu   gosync.Mutex
	used map[string]time.Time
}

func newReplayGuard() *replayGuard { return &replayGuard{used: map[string]time.Time{}} }

// consume reports whether state was unused, and marks it used.
func (g *replayGuard) consume(state string, expires, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for s, exp := range g.used {
		if now.After(exp) {
			delete(g.used, s)
		}
	}
	if _, seen := g.used[state]; seen {
		return false
	}
	g.used[state] = expires
	return true
}
