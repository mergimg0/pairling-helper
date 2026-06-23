package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestAdversarialPairlingConnectBypass is an independent skeptic test verifying
// that ExposureModePairlingConnect denies credential/admin/non-pre-pair paths and
// path-trick variants before reaching the upstream.
func TestAdversarialPairlingConnectBypass(t *testing.T) {
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path+"?raw="+r.URL.RawPath)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 4096,
		Mode:         ExposureModePairlingConnect,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Each case: method, raw target (as sent on the wire), whether we expect it
	// to reach the upstream (forwarded=true) WITHOUT a bearer token.
	cases := []struct {
		name        string
		method      string
		target      string
		wantForward bool
	}{
		// Mint / admin / non-pre-pair — must be denied unauthenticated
		{"mint plain", "POST", "/mint", false},
		{"mint-token", "POST", "/mint-token", false},
		{"pair/start", "POST", "/pair/start", false},
		{"pair/revoke", "POST", "/pair/revoke", false},
		{"pair/rotate-token", "POST", "/pair/rotate-token", false},
		{"spawn-session", "POST", "/spawn-session", false},
		{"internal arbitrary", "GET", "/internal/secrets", false},
		{"send-text no bearer", "POST", "/send-text", false},
		{"sessions no bearer", "GET", "/sessions", false},

		// Path tricks aiming to smuggle /pair/start or /mint past the allowlist
		// while decoding to a dangerous path upstream.
		{"encoded slash pair start", "POST", "/pair%2Fstart", false},
		{"encoded mint", "POST", "/%6dint", false}, // %6d = 'm'
		{"case pair start", "POST", "/PAIR/START", false},
		{"case mint", "POST", "/MINT", false},
		{"double slash pair start", "POST", "//pair/start", false},
		{"double slash send-text", "POST", "//send-text", false},
		{"trailing slash send-text", "POST", "/send-text/", false},
		{"dotdot traversal to start", "POST", "/pair/claim/../start", false},
		{"dotdot to send-text", "POST", "/healthz/../send-text", false},
		{"encoded dotdot", "POST", "/pair/claim/%2e%2e/start", false},
		{"healthz encoded", "GET", "/health%7a", false}, // %7a = 'z' -> /healthz only if decoded for match
		{"semicolon param", "GET", "/healthz;/../send-text", false},
		{"null byte", "POST", "/send-text%00", false},
		{"trailing dot", "POST", "/send-text.", false},

		// Allowed pre-pair paths — these SHOULD forward unauthenticated (sanity)
		{"healthz allowed", "GET", "/healthz", true},
		{"health allowed", "GET", "/health", true},
		{"readyz allowed", "GET", "/readyz", true},
		{"routez allowed", "GET", "/routez", true},
		{"manifest allowed", "GET", "/manifest", true},
		{"pair claim allowed", "POST", "/pair/claim", true},
		{"pair psk-claim allowed", "POST", "/pair/psk-claim", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(forwarded)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "http://pc.local"+tc.target, strings.NewReader("{}"))
			handler.ServeHTTP(rec, req)
			didForward := len(forwarded) > before
			if didForward != tc.wantForward {
				t.Errorf("%s %s: forwarded=%v want=%v (status=%d)", tc.method, tc.target, didForward, tc.wantForward, rec.Code)
			}
		})
	}

	t.Logf("paths that reached upstream: %+v", forwarded)
	// Hard assertion: nothing dangerous must ever appear in the forwarded list.
	joined := fmt.Sprintf("%+v", forwarded)
	for _, danger := range []string{"start", "mint", "spawn", "internal", "revoke", "rotate"} {
		if strings.Contains(strings.ToLower(joined), danger) {
			t.Fatalf("DANGEROUS path reached upstream containing %q: %s", danger, joined)
		}
	}
}
