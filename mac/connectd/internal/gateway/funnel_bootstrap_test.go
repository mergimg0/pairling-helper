package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestFunnelBootstrapAllowlist verifies the public Funnel surface forwards only
// the minimal bootstrap set and default-denies everything else, including any
// bearer-authenticated post-pair path. The bearer fallthrough that
// ExposureModePairlingConnect allows must be structurally unreachable here.
func TestFunnelBootstrapAllowlist(t *testing.T) {
	forwarded := map[string]bool{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded[r.Method+" "+r.URL.Path] = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 4096,
		Mode:         ExposureModeFunnelBootstrap,
	})
	if err != nil {
		t.Fatal(err)
	}

	type tc struct {
		method string
		path   string
		bearer bool
	}

	allowed := []tc{
		{http.MethodGet, "/health", false},
		{http.MethodGet, "/healthz", false},
		{http.MethodGet, "/readyz", false},
		{http.MethodGet, "/manifest", false},
		{http.MethodPost, "/pair/psk-claim", false},
	}

	// Every one of these must be denied, even with a valid-looking bearer, since
	// the funnel mode has no bearer post-pair fallthrough.
	denied := []tc{
		{http.MethodPost, "/pair/start", false},
		{http.MethodPost, "/pair/claim", false},
		{http.MethodPost, "/pair/reauth-challenge", false},
		{http.MethodPost, "/pair/reauth-claim", false},
		{http.MethodGet, "/routez", false},
		{http.MethodPost, "/internal/session-register", true},
		{http.MethodPost, "/spawn-session", true},
		{http.MethodPost, "/send-text", true},
		{http.MethodGet, "/sessions", true},
		{http.MethodPost, "/pairling-tools/run", true},
		{http.MethodPost, "/pair/revoke", true},
		{http.MethodPost, "/pair/rotate-token", true},
	}

	send := func(c tc) *httptest.ResponseRecorder {
		var body string
		if c.method == http.MethodPost {
			body = "{}"
		}
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(body))
		if c.bearer {
			req.Header.Set("Authorization", "Bearer testtoken")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	for _, c := range allowed {
		rec := send(c)
		if rec.Code != http.StatusOK {
			t.Errorf("allowed %s %s: got %d, want 200", c.method, c.path, rec.Code)
		}
		// Note: /health, /healthz, /manifest are answered by connectd (synthesized)
		// and do not reach upstream; that is asserted in the synthesis test.
	}

	for _, c := range denied {
		rec := send(c)
		if rec.Code == http.StatusOK {
			t.Errorf("denied %s %s (bearer=%v): returned 200, must be blocked", c.method, c.path, c.bearer)
		}
		if forwarded[c.method+" "+c.path] {
			t.Errorf("denied %s %s (bearer=%v): reached upstream, must be blocked at the gateway", c.method, c.path, c.bearer)
		}
	}
}

// TestFunnelBootstrapIsStrictSubsetOfPrePair asserts the funnel set never admits
// a path the pre-pair set denies, and is strictly smaller (excludes /routez and
// /pair/claim). This guards against the funnel mode drifting wider than pre-pair.
func TestFunnelBootstrapIsStrictSubsetOfPrePair(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		for path := range funnelBootstrapGetPaths {
			if m == http.MethodGet && !prePairAllowed(http.MethodGet, path) {
				t.Errorf("funnel GET %s not allowed by pre-pair: funnel must be a subset", path)
			}
		}
		for path := range funnelBootstrapPostPaths {
			if m == http.MethodPost && !prePairAllowed(http.MethodPost, path) {
				t.Errorf("funnel POST %s not allowed by pre-pair: funnel must be a subset", path)
			}
		}
	}
	if funnelBootstrapGetPaths["/routez"] {
		t.Error("/routez must be excluded from the funnel surface")
	}
	if funnelBootstrapPostPaths["/pair/claim"] {
		t.Error("/pair/claim must be excluded from the funnel surface")
	}
	if funnelBootstrapPostPaths["/pair/start"] {
		t.Error("/pair/start must never be on the funnel surface")
	}
}

// TestFunnelHealthAndManifestAreSynthesizedNotProxied verifies connectd answers
// funnel /health and /manifest itself with a minimal body and never proxies the
// upstream's identity, install path, version, or route topology. /readyz still
// proxies, since it is the readiness probe.
func TestFunnelHealthAndManifestAreSynthesizedNotProxied(t *testing.T) {
	upstreamHit := map[string]bool{}
	sensitive := `{"ok":true,"install_id":"inst_secret","computer_name":"Bob-MacBook","runtime":{"install_root":"/Users/bob/x","runtime_version":"0.2.5"},"routes":[{"host":"10.0.0.1"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit[r.URL.Path] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sensitive))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	handler, err := NewHandler(Options{
		Upstream:        upstreamURL,
		MaxBodyBytes:    4096,
		Mode:            ExposureModeFunnelBootstrap,
		FunnelMacIDHash: "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/health", "/manifest"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", path, rec.Code)
		}
		body := rec.Body.String()
		for _, leak := range []string{"inst_secret", "Bob-MacBook", "install_root", "runtime_version", "routes", "10.0.0.1"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s response leaked %q: %s", path, leak, body)
			}
		}
		if !strings.Contains(body, "deadbeef") {
			t.Errorf("%s response missing mac_id_hash: %s", path, body)
		}
		if upstreamHit[path] {
			t.Errorf("%s reached upstream; must be synthesized at connectd", path)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !upstreamHit["/readyz"] {
		t.Error("/readyz should be proxied to upstream, not synthesized")
	}
}

// TestFunnelLimiterCaps verifies the three identity-independent caps: per-pair_id
// isolation, the in-flight ECDH concurrency cap, and the global ceiling.
func TestFunnelLimiterCaps(t *testing.T) {
	// Per-pair cap = 2, global and ecdh high.
	l := NewFunnelLimiter(1000, 2, 100)
	r1, ok := l.Acquire("pairA")
	if !ok {
		t.Fatal("1st pairA should pass")
	}
	r2, ok := l.Acquire("pairA")
	if !ok {
		t.Fatal("2nd pairA should pass")
	}
	if _, ok := l.Acquire("pairA"); ok {
		t.Error("3rd pairA should be capped")
	}
	if rB, ok := l.Acquire("pairB"); !ok {
		t.Error("pairB must be unaffected by pairA's cap (per-pair isolation)")
	} else {
		rB()
	}
	r1()
	r2()

	// ECDH concurrency cap = 1: an unreleased acquire blocks the next.
	l2 := NewFunnelLimiter(1000, 1000, 1)
	rel, ok := l2.Acquire("x")
	if !ok {
		t.Fatal("first ecdh slot should acquire")
	}
	if _, ok := l2.Acquire("y"); ok {
		t.Error("ecdh cap=1: a second concurrent acquire must fail")
	}
	rel()
	if r, ok := l2.Acquire("z"); !ok {
		t.Error("after release, the ecdh slot should be free")
	} else {
		r()
	}

	// Global ceiling = 2: a third request fails even with a fresh pair_id.
	l3 := NewFunnelLimiter(2, 1000, 1000)
	if _, ok := l3.Acquire("a"); !ok {
		t.Fatal("global 1 should pass")
	}
	if _, ok := l3.Acquire("b"); !ok {
		t.Fatal("global 2 should pass")
	}
	if _, ok := l3.Acquire("c"); ok {
		t.Error("global ceiling=2: a third request must fail even with a new pair_id")
	}
}

// TestFunnelMarkerInjectedAndStripped verifies connectd sets the funnel-origin
// marker only on the funnel handler (replacing any inbound spoof) and strips it
// on the tailnet handler.
func TestFunnelMarkerInjectedAndStripped(t *testing.T) {
	var gotMarker string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMarker = r.Header.Get("X-Pairling-Funnel-Origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	funnel, err := NewHandler(Options{Upstream: upstreamURL, Mode: ExposureModeFunnelBootstrap, FunnelLimiter: NewFunnelLimiter(1000, 1000, 1000)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/pair/psk-claim", strings.NewReader(`{"pair_id":"p"}`))
	req.Header.Set("X-Pairling-Funnel-Origin", "spoofed")
	funnel.ServeHTTP(httptest.NewRecorder(), req)
	if gotMarker != "1" {
		t.Errorf("funnel handler upstream marker = %q, want \"1\" (inbound spoof must be replaced)", gotMarker)
	}

	gotMarker = ""
	tailnet, err := NewHandler(Options{Upstream: upstreamURL, Mode: ExposureModePairlingConnect})
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req2.Header.Set("X-Pairling-Funnel-Origin", "spoofed")
	tailnet.ServeHTTP(httptest.NewRecorder(), req2)
	if gotMarker != "" {
		t.Errorf("tailnet handler upstream marker = %q, want empty (must be stripped)", gotMarker)
	}
}
