package gateway

// SPEC-p5 §5 — the security review as an executable adversarial test. An
// independent skeptic drives the §1 trap list plus path-trick smuggling
// through a live ExposureModeSSH handler WITH a valid bearer (the SSH pipe
// always carries one). Nothing dangerous — pairing, mint, internal, the
// status server's auth/open, or an escaped separator — may reach the
// upstream. Provenance is the gateway's own ssh_gateway, never the client's.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdversarialSSHGatewayBypass(t *testing.T) {
	var forwarded []string
	var forwardedProvenance []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		forwardedProvenance = append(forwardedProvenance, r.Header.Get("X-Pairling-Peer-Provenance"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 4096,
		Mode:         ExposureModeSSH,
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		method      string
		target      string
		wantForward bool
	}{
		// §1 trap list — every one blocked even WITH a bearer.
		{"pair/start", "POST", "/pair/start", false},
		{"pair/claim", "POST", "/pair/claim", false},
		{"pair/psk-activate", "POST", "/pair/psk-activate", false},
		{"pair/psk-claim", "POST", "/pair/psk-claim", false},
		{"pair/psk-claim-v2", "POST", "/pair/psk-claim-v2", false},
		{"pair/revoke", "POST", "/pair/revoke", false},
		{"pair/rotate-token", "POST", "/pair/rotate-token", false},
		{"pair/bind-node", "POST", "/pair/bind-node", false},
		{"mint", "POST", "/mint", false},
		{"internal register", "POST", "/internal/session-register", false},
		{"internal arbitrary", "GET", "/internal/secrets", false},
		{"auth/open (status server)", "GET", "/auth/open", false},

		// Path-trick smuggling toward /pair/start or /mint.
		{"encoded slash pair start", "POST", "/pair%2Fstart", false},
		{"encoded backslash", "GET", "/sessions%5cx", false},
		{"encoded mint", "POST", "/%6dint", false},
		{"case pair start", "POST", "/PAIR/START", false},
		{"double slash pair start", "POST", "//pair/start", false},
		{"dotdot traversal to start", "POST", "/sessions/../pair/start", false},
		{"encoded dotdot", "POST", "/sessions/%2e%2e/pair/start", false},
		{"null byte send-text smuggle", "POST", "/pair/start%00", false},

		// Allowed post-pair surface WITH bearer — sanity that the pipe works.
		{"sessions", "GET", "/sessions", true},
		{"send-text", "POST", "/send-text", true},
		{"terminal-input", "POST", "/terminal-input", true},
		{"pairdrop upload", "POST", "/pairdrop/files", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(forwarded)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "http://ssh.local"+tc.target, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer device-token")
			// The client tries to forge honest-looking provenance; the
			// gateway must overwrite it.
			req.Header.Set("X-Pairling-Peer-Provenance", "pairling_connectd")
			handler.ServeHTTP(rec, req)
			didForward := len(forwarded) > before
			if didForward != tc.wantForward {
				t.Errorf("%s %s: forwarded=%v want=%v (status=%d)", tc.method, tc.target, didForward, tc.wantForward, rec.Code)
			}
		})
	}

	joined := fmt.Sprintf("%+v", forwarded)
	for _, danger := range []string{"start", "mint", "spawn", "internal", "revoke", "rotate", "auth/open"} {
		if strings.Contains(strings.ToLower(joined), danger) {
			t.Fatalf("DANGEROUS path reached upstream containing %q: %s", danger, joined)
		}
	}
	// Every forwarded request must carry gateway-injected ssh_gateway
	// provenance — never the client's forged pairling_connectd.
	for _, prov := range forwardedProvenance {
		if prov != "" && prov != "ssh_gateway" {
			t.Fatalf("forged provenance reached upstream: %q", prov)
		}
	}
}

func TestAdversarialSSHGatewayCapsBodyBeforeForwarding(t *testing.T) {
	var forwarded int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 32,
		Mode:         ExposureModeSSH,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://ssh.local/send-text", strings.NewReader(strings.Repeat("x", 33)))
	req.Header.Set("Authorization", "Bearer device-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if forwarded != 0 {
		t.Fatalf("oversized SSH request reached upstream")
	}
}

func TestAdversarialSSHGatewayRateLimitsAllowedRequests(t *testing.T) {
	var forwarded int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 4096,
		Mode:         ExposureModeSSH,
		RateLimiter:  NewMemoryRateLimiter(1, time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "http://ssh.local/sessions", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer device-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("request %d status = %d, want %d", i+1, rec.Code, want)
		}
	}
	if forwarded != 1 {
		t.Fatalf("forwarded = %d, want 1", forwarded)
	}
}
