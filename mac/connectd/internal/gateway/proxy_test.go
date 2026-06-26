package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingLogger struct {
	mu     sync.Mutex
	events []Event
}

type peerNodeResolverFunc func(context.Context, string) (string, string, bool)

func (f peerNodeResolverFunc) PeerNodeID(ctx context.Context, remoteAddr string) (string, string, bool) {
	return f(ctx, remoteAddr)
}

func (l *recordingLogger) Log(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *recordingLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return fmt.Sprintf("%+v", l.events)
}

func TestHandlerForwardsAllowedRequestAndPreservesAuthProofHeaders(t *testing.T) {
	var sawRequest bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.URL.RequestURI(); got != "/send-text?session=s-1" {
			t.Fatalf("request URI = %s", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"text":"hello"}` {
			t.Fatalf("body = %q", string(body))
		}
		for _, header := range []string{
			"Authorization",
			"Pairling-Install-ID",
			"Pairling-Request-ID",
			"Pairling-Timestamp",
			"Pairling-Body-SHA256",
			"Pairling-Proof",
			"X-Pairling-Action-Id",
		} {
			if r.Header.Get(header) == "" {
				t.Fatalf("missing forwarded header %s", header)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL, 1024, nil)
	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text?session=s-1", strings.NewReader(`{"text":"hello"}`))
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("Pairling-Install-ID", "inst_test")
	req.Header.Set("Pairling-Request-ID", "req_test")
	req.Header.Set("Pairling-Timestamp", "1779490000000")
	req.Header.Set("Pairling-Body-SHA256", "bodyhash")
	req.Header.Set("Pairling-Proof", "proof")
	req.Header.Set("X-Pairling-Action-Id", "action-1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !sawRequest {
		t.Fatal("upstream did not receive allowed request")
	}
}

func TestHandlerRejectsDisallowedTrafficBeforeUpstream(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, 1024, nil)

	cases := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"unknown path", http.MethodGet, "http://pairling-connect.local/debug/pprof", http.StatusNotFound},
		{"unsupported method on allowed path", http.MethodDelete, "http://pairling-connect.local/healthz", http.StatusMethodNotAllowed},
		{"connect proxy method", http.MethodConnect, "http://pairling-connect.local/healthz", http.StatusMethodNotAllowed},
		{"arbitrary proxy-looking path", http.MethodGet, "http://pairling-connect.local/http://127.0.0.1:7773/healthz", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestAllowedApertureCLIRoutesStayPairlingScoped(t *testing.T) {
	allowedGET := []string{
		"/aperture-cli/launch-contexts",
		"/aperture-cli/status",
		"/aperture-cli/providers",
	}
	for _, path := range allowedGET {
		if !Allowed(http.MethodGet, path) {
			t.Fatalf("GET %s should be allowed", path)
		}
		if Allowed(http.MethodPost, path) {
			t.Fatalf("POST %s should not be allowed", path)
		}
	}
	if !Allowed(http.MethodPost, "/aperture-cli/open") {
		t.Fatal("POST /aperture-cli/open should be allowed for proof-bound manual TUI launch")
	}
	if Allowed(http.MethodGet, "/aperture-cli/open") {
		t.Fatal("GET /aperture-cli/open should not be allowed")
	}
	disallowed := []string{
		"/aperture-proxy/api/providers",
		"/aperture-cli/config",
		"/aperture-cli/providers/openai",
		"/v1/responses",
		"/v1/messages",
		"/v1/chat/completions",
	}
	for _, path := range disallowed {
		if Allowed(http.MethodGet, path) || Allowed(http.MethodPost, path) {
			t.Fatalf("%s should not be allowed", path)
		}
	}
}

func TestAllowedOrchestrationRoutesAreMethodScoped(t *testing.T) {
	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/orchestrations"},
		{http.MethodPost, "/orchestrations"},
		{http.MethodGet, "/orchestrations/orchestration-abc123"},
		{http.MethodGet, "/orchestrations/orchestration-abc123/stream"},
		{http.MethodPost, "/orchestrations/orchestration-abc123/stop"},
	}
	for _, tc := range allowed {
		if !Allowed(tc.method, tc.path) {
			t.Fatalf("%s %s should be allowed", tc.method, tc.path)
		}
	}

	disallowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/orchestrations/orchestration-abc123/stop"},
		{http.MethodPost, "/orchestrations/orchestration-abc123/stream"},
		{http.MethodPost, "/orchestrations/orchestration-abc123"},
		{http.MethodGet, "/orchestrations/orchestration-abc123/nested/stream"},
		{http.MethodPost, "/orchestrations/orchestration-abc123/nested/stop"},
	}
	for _, tc := range disallowed {
		if Allowed(tc.method, tc.path) {
			t.Fatalf("%s %s should not be allowed", tc.method, tc.path)
		}
	}
}

func TestAllowedSessionSourceDiagnosticsIsGetOnly(t *testing.T) {
	if !Allowed(http.MethodGet, "/session-source-diagnostics") {
		t.Fatal("GET /session-source-diagnostics should be allowed")
	}
	if Allowed(http.MethodPost, "/session-source-diagnostics") {
		t.Fatal("POST /session-source-diagnostics should not be allowed")
	}
}

func TestAllowedPairDropContentRouteIsGetOnlyAndPathStrict(t *testing.T) {
	if !Allowed(http.MethodGet, "/pairdrop/files/pd_0123456789abcdef0123456789abcdef/content") {
		t.Fatal("GET PairDrop content route should be allowed")
	}
	rejected := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/pairdrop/files/pd_0123456789abcdef0123456789abcdef/content"},
		{http.MethodGet, "/pairdrop/files/pd_0123456789abcdef0123456789abcdef/content/extra"},
		{http.MethodGet, "/pairdrop/files/pd_0123456789abcdef0123456789abcdef/extra/content"},
	}
	for _, tc := range rejected {
		if Allowed(tc.method, tc.path) {
			t.Fatalf("%s %s should not be allowed", tc.method, tc.path)
		}
	}
}

func TestHandlerEnforcesRequestBodyLimitBeforeUpstream(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, 8, nil)

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader("0123456789"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestHandlerLogsMetadataWithoutSensitiveBodies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	logger := &recordingLogger{}
	handler := newTestHandler(t, upstream.URL, 1024, logger)

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{"text":"sk-secret prompt transcript"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	logged := logger.joined()
	for _, sensitive := range []string{"sk-secret", "prompt", "transcript"} {
		if strings.Contains(logged, sensitive) {
			t.Fatalf("log leaked %q: %s", sensitive, logged)
		}
	}
	if !strings.Contains(logged, "/send-text") {
		t.Fatalf("log missing endpoint metadata: %s", logged)
	}
}

func TestNewHandlerRejectsNonLocalUpstream(t *testing.T) {
	cases := []string{
		"http://example.com:7773",
		"http://10.0.0.20:7773",
		"http://192.168.1.20:7773",
	}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			upstreamURL, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewHandler(Options{Upstream: upstreamURL}); err == nil {
				t.Fatal("NewHandler accepted non-local upstream")
			}
		})
	}
}

func TestNewHandlerAcceptsLoopbackUpstream(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:7773",
		"http://localhost:7773",
		"http://[::1]:7773",
	}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			upstreamURL, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewHandler(Options{Upstream: upstreamURL}); err != nil {
				t.Fatalf("NewHandler rejected loopback upstream: %v", err)
			}
		})
	}
}

func TestPrePairModeOnlyAllowsHealthManifestRoutezAndClaims(t *testing.T) {
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModePrePair, nil)

	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/health"},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/routez"},
		{http.MethodGet, "/manifest"},
		{http.MethodPost, "/pair/claim"},
		{http.MethodPost, "/pair/psk-claim"},
	}
	for _, tc := range allowed {
		t.Run("allows "+tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, "http://pairling-connect.local"+tc.path, strings.NewReader(`{}`)))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}

	rejected := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/pair/start", http.StatusNotFound},
		{http.MethodGet, "/sessions", http.StatusNotFound},
		{http.MethodGet, "/sessions-stream", http.StatusNotFound},
		{http.MethodPost, "/send-text", http.StatusNotFound},
		{http.MethodPost, "/terminal-control", http.StatusNotFound},
		{http.MethodPost, "/worker-kill", http.StatusNotFound},
		{http.MethodPost, "/push/preferences", http.StatusNotFound},
		{http.MethodPost, "/push/permission/allow", http.StatusNotFound},
		{http.MethodPost, "/safety/ack", http.StatusNotFound},
		{http.MethodPost, "/aperture-cli/open", http.StatusNotFound},
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodPost, "/health", http.StatusMethodNotAllowed},
	}
	for _, tc := range rejected {
		t.Run("policy "+tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, "http://pairling-connect.local"+tc.path, strings.NewReader(`{}`)))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	if len(forwarded) != len(allowed)+1 {
		t.Fatalf("forwarded = %+v", forwarded)
	}
}

func TestPairlingConnectModeRequiresBearerForPostPairEndpointsAndRejectsRemotePairStart(t *testing.T) {
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModePairlingConnect, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized send-text status = %d body = %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer device-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized send-text status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/pair/start", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer device-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("remote pair/start status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/pair/claim", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-pair claim status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/pair/psk-claim", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-pair PSK claim status = %d body = %s", rec.Code, rec.Body.String())
	}

	if fmt.Sprintf("%+v", forwarded) != "[POST /send-text POST /pair/claim POST /pair/psk-claim]" {
		t.Fatalf("forwarded = %+v", forwarded)
	}
}

func TestPairlingConnectStripsForgedPeerNodeHeader(t *testing.T) {
	var forwardedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeader = r.Header.Get("X-Pairling-Peer-Node")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModePairlingConnect, nil)

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{"tailnet_node_id":"forged-body"}`))
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("X-Pairling-Peer-Node", "forged-header")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if forwardedHeader != "" {
		t.Fatalf("forged peer-node header forwarded to upstream: %q", forwardedHeader)
	}
}

func TestPairlingConnectSetsPeerNodeHeaderFromResolver(t *testing.T) {
	var forwardedHeader string
	var forwardedProvenance string
	var resolvedRemote string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeader = r.Header.Get("X-Pairling-Peer-Node")
		forwardedProvenance = r.Header.Get("X-Pairling-Peer-Provenance")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 1024,
		Mode:         ExposureModePairlingConnect,
		PeerNodeResolver: peerNodeResolverFunc(func(_ context.Context, remoteAddr string) (string, string, bool) {
			resolvedRemote = remoteAddr
			return "nPeerCNTRL", "tagged", true
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{}`))
	req.RemoteAddr = "100.64.0.50:12345"
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("X-Pairling-Peer-Node", "forged-header")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if resolvedRemote != "100.64.0.50:12345" {
		t.Fatalf("resolver remote addr = %q", resolvedRemote)
	}
	if forwardedHeader != "nPeerCNTRL" {
		t.Fatalf("peer-node header = %q, want trusted resolver value", forwardedHeader)
	}
	if forwardedProvenance != "tagged" {
		t.Fatalf("peer-provenance header = %q, want tagged", forwardedProvenance)
	}
}

// TestRewriteStripsForgedProvenanceAndReinjectsFromResolver proves the rewrite
// step deletes BOTH client-supplied X-Pairling-Peer-Node and
// X-Pairling-Peer-Provenance headers, then re-injects them from the resolver's
// trusted return values. A forged "tagged" provenance from the client must not
// survive when the resolver reports "interactive".
func TestRewriteStripsForgedProvenanceAndReinjectsFromResolver(t *testing.T) {
	var forwardedHeader string
	var forwardedProvenance string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeader = r.Header.Get("X-Pairling-Peer-Node")
		forwardedProvenance = r.Header.Get("X-Pairling-Peer-Provenance")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 1024,
		Mode:         ExposureModePairlingConnect,
		PeerNodeResolver: peerNodeResolverFunc(func(_ context.Context, _ string) (string, string, bool) {
			return "nResolverIOS", "interactive", true
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{}`))
	req.RemoteAddr = "100.64.0.50:12345"
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("X-Pairling-Peer-Node", "forged-node")
	req.Header.Set("X-Pairling-Peer-Provenance", "tagged")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if forwardedHeader != "nResolverIOS" {
		t.Fatalf("peer-node header = %q, want resolver value nResolverIOS", forwardedHeader)
	}
	if forwardedProvenance != "interactive" {
		t.Fatalf("peer-provenance header = %q, want resolver value interactive", forwardedProvenance)
	}
}

// TestRewriteInjectsNoHeadersWhenResolverRejects proves that when the resolver
// returns ok=false, NEITHER the peer-node NOR the peer-provenance header reaches
// the upstream, and any client-supplied copies are stripped.
func TestRewriteInjectsNoHeadersWhenResolverRejects(t *testing.T) {
	var sawNode bool
	var sawProvenance bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawNode = r.Header["X-Pairling-Peer-Node"]
		_, sawProvenance = r.Header["X-Pairling-Peer-Provenance"]
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: 1024,
		Mode:         ExposureModePairlingConnect,
		PeerNodeResolver: peerNodeResolverFunc(func(_ context.Context, _ string) (string, string, bool) {
			return "", "", false
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local/send-text", strings.NewReader(`{}`))
	req.RemoteAddr = "100.64.0.50:12345"
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("X-Pairling-Peer-Node", "forged-node")
	req.Header.Set("X-Pairling-Peer-Provenance", "interactive")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if sawNode {
		t.Fatal("peer-node header reached upstream when resolver rejected")
	}
	if sawProvenance {
		t.Fatal("peer-provenance header reached upstream when resolver rejected")
	}
}

func TestPairlingConnectModeMatchesEndpointContract(t *testing.T) {
	contract := loadEndpointContractForTesting(t)
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModePairlingConnect, nil)

	for _, row := range contract.Rows {
		if !row.AssertConnectdParity {
			continue
		}
		req := httptest.NewRequest(row.Method, "http://pairling-connect.local"+row.SamplePath, strings.NewReader(`{}`))
		if row.BearerRequired {
			req.Header.Set("Authorization", "Bearer device-token")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		got := rec.Code == http.StatusOK
		if got != row.ConnectdPairlingConnect {
			t.Fatalf("%s %s connectd allowed = %t, want %t (status=%d body=%s)", row.Method, row.SamplePath, got, row.ConnectdPairlingConnect, rec.Code, rec.Body.String())
		}
	}
	if len(forwarded) == 0 {
		t.Fatal("contract did not exercise any forwarded connectd rows")
	}
}

func TestPrePairClaimsAreRateLimitedAndBodyLimited(t *testing.T) {
	for _, path := range []string{"/pair/claim", "/pair/psk-claim"} {
		t.Run(path, func(t *testing.T) {
			var upstreamCalls int
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			limiter := NewMemoryRateLimiter(1, time.Minute)
			handler := newTestHandlerWithMode(t, upstream.URL, defaultMaxBodyBytes, nil, ExposureModePrePair, limiter)

			req := httptest.NewRequest(http.MethodPost, "http://pairling-connect.local"+path, strings.NewReader(`{}`))
			req.RemoteAddr = "100.64.0.8:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("first claim status = %d body = %s", rec.Code, rec.Body.String())
			}

			req = httptest.NewRequest(http.MethodPost, "http://pairling-connect.local"+path, strings.NewReader(`{}`))
			req.RemoteAddr = "100.64.0.8:12345"
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("second claim status = %d body = %s", rec.Code, rec.Body.String())
			}

			largeBody := strings.NewReader(strings.Repeat("x", int(prePairMaxBodyBytes)+1))
			req = httptest.NewRequest(http.MethodPost, "http://pairling-connect.local"+path, largeBody)
			req.RemoteAddr = "100.64.0.9:12345"
			req.ContentLength = prePairMaxBodyBytes + 1
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("large claim status = %d body = %s", rec.Code, rec.Body.String())
			}

			if upstreamCalls != 1 {
				t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
			}
		})
	}
}

type endpointContractForTesting struct {
	Rows []endpointContractRowForTesting `json:"rows"`
}

type endpointContractRowForTesting struct {
	Method                  string `json:"method"`
	SamplePath              string `json:"sample_path"`
	ConnectdPairlingConnect bool   `json:"connectd_pairling_connect"`
	BearerRequired          bool   `json:"bearer_required"`
	AssertConnectdParity    bool   `json:"assert_connectd_parity"`
}

func loadEndpointContractForTesting(t *testing.T) endpointContractForTesting {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "thoughts", "shared", "contracts", "pairling-connect-endpoints.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract endpointContractForTesting
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

func newTestHandler(t *testing.T, upstream string, maxBody int64, logger Logger) http.Handler {
	return newTestHandlerWithMode(t, upstream, maxBody, logger, ExposureModePostPair, nil)
}

func newTestHandlerWithMode(t *testing.T, upstream string, maxBody int64, logger Logger, mode ExposureMode, limiter RateLimiter) http.Handler {
	t.Helper()
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream:     upstreamURL,
		MaxBodyBytes: maxBody,
		Mode:         mode,
		Logger:       logger,
		RateLimiter:  limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
