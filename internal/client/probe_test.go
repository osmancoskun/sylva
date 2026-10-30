package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/tree"
	"github.com/osman/sylva/internal/vault"
)

type probeFixture struct {
	reader, writer *sylva.Vault
	store          *storage.SQLiteStore
	domainRequests *atomic.Int32
}

// Intercept only login-list requests, after a successful token lookup. Failures
// must abort the whole probe rather than returning that earlier token match.
func newProbeFixture(t *testing.T, cache bool, timeout time.Duration, intercept func(http.ResponseWriter, *http.Request) bool) probeFixture {
	t.Helper()
	cfg, store := keyCheckServer(t)
	ctx := context.Background()
	writer := openKeyCheckVault(t, cfg)
	if err := writer.Unlock(ctx, "probe passphrase"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, writer, "synthetic token secret")
	if _, err := writer.LoginSet(ctx, "example.test", "", "synthetic domain secret", false, false); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(cfg.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	reverse := httputil.NewSingleHostReverseProxy(target)
	requests := new(atomic.Int32)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/records" && r.URL.Query().Get("type") == string(vault.SecretTypeLogin) {
			requests.Add(1)
			if intercept != nil && intercept(w, r) {
				return
			}
		}
		reverse.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	cfg.ServerURL = proxy.URL
	cfg.CacheEnabled = cache
	cfg.CachePath = filepath.Join(t.TempDir(), "cache.db")
	if timeout > 0 {
		cfg.Timeout = timeout
	}
	reader := openKeyCheckVault(t, cfg)
	if err := reader.Unlock(ctx, "probe passphrase"); err != nil {
		t.Fatal(err)
	}
	return probeFixture{reader: reader, writer: writer, store: store, domainRequests: requests}
}

func TestProbePropagatesDomainHTTPFailuresWithCache(t *testing.T) {
	for _, code := range []int{401, 403, 404, 413, 500} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var fail atomic.Bool
			f := newProbeFixture(t, true, 0, func(w http.ResponseWriter, r *http.Request) bool {
				if !fail.Load() {
					return false
				}
				http.Error(w, "domain lookup failed", code)
				return true
			})
			if _, err := f.reader.ListSecrets(context.Background(), vault.SecretTypeLogin); err != nil {
				t.Fatal(err)
			}
			fail.Store(true)
			matches, err := f.reader.ProbeValues(context.Background(), "shared-token", false, "")
			var response *transport.HTTPError
			if matches != nil || !errors.As(err, &response) || response.Status != code {
				t.Fatalf("HTTP failure hidden behind matches/cache: %v %v", matches, err)
			}
			if !strings.Contains(err.Error(), "probe domain") {
				t.Fatalf("missing failing type context: %v", err)
			}
			kind, value, err := f.reader.GetValue(context.Background(), "shared-token", "", false, "")
			if kind != "" || value != "" || !errors.As(err, &response) || response.Status != code {
				t.Fatal("automatic lookup returned a partial secret")
			}
		})
	}
}

func TestProbePropagatesMalformedDomainResponses(t *testing.T) {
	for name, body := range map[string]string{"syntax": "not JSON", "missing records": "{}", "null records": `{"records":null}`, "null": "null", "wrong shape": "[]"} {
		t.Run(name, func(t *testing.T) {
			f := newProbeFixture(t, false, 0, func(w http.ResponseWriter, r *http.Request) bool { _, _ = io.WriteString(w, body); return true })
			matches, err := f.reader.ProbeValues(context.Background(), "shared-token", false, "")
			if matches != nil || err == nil || !strings.Contains(err.Error(), "probe domain") {
				t.Fatalf("malformed response hidden: %v %v", matches, err)
			}
		})
	}
}

func TestProbePropagatesDomainConnectionFailure(t *testing.T) {
	f := newProbeFixture(t, false, 0, func(w http.ResponseWriter, r *http.Request) bool {
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test server cannot hijack")
			w.WriteHeader(500)
			return true
		}
		conn, _, err := h.Hijack()
		if err != nil {
			t.Error(err)
			return true
		}
		_ = conn.Close()
		return true
	})
	matches, err := f.reader.ProbeValues(context.Background(), "shared-token", false, "")
	var requestErr *url.Error
	if matches != nil || !errors.As(err, &requestErr) {
		t.Fatalf("connection failure hidden: %v %v", matches, err)
	}
}

func TestProbePropagatesDomainTimeout(t *testing.T) {
	f := newProbeFixture(t, false, 150*time.Millisecond, func(w http.ResponseWriter, r *http.Request) bool { <-r.Context().Done(); return true })
	matches, err := f.reader.ProbeValues(context.Background(), "shared-token", false, "")
	if matches != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout hidden: %v %v", matches, err)
	}
}

func TestProbePropagatesCancellationDuringDomainLookup(t *testing.T) {
	entered := make(chan struct{}, 1)
	f := newProbeFixture(t, false, 0, func(w http.ResponseWriter, r *http.Request) bool {
		entered <- struct{}{}
		<-r.Context().Done()
		return true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		matches, err := f.reader.ProbeValues(ctx, "shared-token", false, "")
		if matches != nil {
			t.Error("canceled probe returned partial matches")
		}
		done <- err
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("domain lookup did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation hidden: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled probe did not stop")
	}
}

func TestProbePropagatesCorruptedLoginDespiteCachedData(t *testing.T) {
	f := newProbeFixture(t, true, 0, nil)
	ctx := context.Background()
	if _, err := f.reader.ListSecrets(ctx, vault.SecretTypeLogin); err != nil {
		t.Fatal(err)
	}
	recs, err := f.store.List(ctx, vault.SecretTypeLogin)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatal("missing login fixture")
	}
	recs[0].Envelope.Ciphertext[0] ^= 1
	if err := f.store.Upsert(ctx, recs[0]); err != nil {
		t.Fatal(err)
	}
	matches, err := f.reader.ProbeValues(ctx, "shared-token", false, "")
	if matches != nil || !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("corrupted login hidden: %v %v", matches, err)
	}
	if strings.Contains(err.Error(), "synthetic domain secret") {
		t.Fatal("error exposed a plaintext secret")
	}
}

func TestProbeDistinguishesInvalidStoredDomainFromInvalidInput(t *testing.T) {
	f := newProbeFixture(t, false, 0, nil)
	ctx := context.Background()
	key, err := f.writer.CopyMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(key)
	item := &vault.SecretItem{ID: "malformed-login", Type: vault.SecretTypeLogin, Identifier: "malformed-login", Login: &vault.LoginPayload{Domain: "/", Password: "synthetic malformed login"}}
	rec, err := vault.Seal(key, item, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.writer.Remote().PutRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	matches, err := f.reader.ProbeValues(ctx, "shared-token", false, "")
	if matches != nil || !errors.Is(err, tree.ErrEmptyDomain) {
		t.Fatalf("invalid stored domain was skipped: %v %v", matches, err)
	}
}

func TestProbePropagatesInheritanceCycles(t *testing.T) {
	f := newProbeFixture(t, false, 0, nil)
	ctx := context.Background()
	for name, parent := range map[string]string{"a.example.test": "b.example.test", "b.example.test": "a.example.test"} {
		if err := f.writer.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeLogin, Identifier: name, ParentID: parent, Login: &vault.LoginPayload{Domain: name, InheritFromParent: true, ParentDomain: parent}}); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := f.reader.ProbeValues(ctx, "a.example.test", false, "")
	if matches != nil || !errors.Is(err, tree.ErrInheritanceCycle) {
		t.Fatalf("inheritance cycle hidden: %v %v", matches, err)
	}
}

func TestNonDomainIdentifiersStillProbeOtherTypes(t *testing.T) {
	for _, identifier := range []string{"bad..name", "https://[invalid", "/"} {
		t.Run(identifier, func(t *testing.T) {
			f := newProbeFixture(t, false, 0, func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(500); return true })
			if err := f.writer.PutSecret(context.Background(), &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: identifier, Token: &vault.TokenPayload{Name: identifier, Token: "opaque identifier secret"}}); err != nil {
				t.Fatal(err)
			}
			matches, err := f.reader.ProbeValues(context.Background(), identifier, false, "")
			if err != nil || len(matches) != 1 || matches[0].Type != vault.SecretTypeToken || matches[0].Value != "opaque identifier secret" {
				t.Fatalf("non-domain identifier: %v %v", matches, err)
			}
			if f.domainRequests.Load() != 0 {
				t.Fatal("invalid domain input triggered a domain lookup")
			}
		})
	}
}

func TestProbeKeepsMissingAndNormalizedDomainBehavior(t *testing.T) {
	f := newProbeFixture(t, false, 0, nil)
	ctx := context.Background()
	_, value, err := f.reader.GetValue(ctx, "shared-token", "", false, "")
	if err != nil || value != "synthetic token secret" {
		t.Fatalf("missing domain blocked token: %v", err)
	}
	if _, _, err := f.reader.GetValue(ctx, "missing.example.test", "", false, ""); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing entry: %v", err)
	}
	kind, value, err := f.reader.GetValue(ctx, "https://EXAMPLE.TEST:8443/path", "", false, "")
	if err != nil || kind != vault.SecretTypeLogin || value != "synthetic domain secret" {
		t.Fatalf("normalized domain: %v", err)
	}
	if _, err := f.reader.ProbeValues(ctx, " \t", false, ""); err == nil {
		t.Fatal("blank identifier accepted")
	}
}
