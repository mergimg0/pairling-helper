package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
		{http.MethodPost, "/pair/psk-activate", false},
		{http.MethodPost, "/pair/psk-claim-v2", false},
	}

	// Every one of these must be denied, even with a valid-looking bearer, since
	// the funnel mode has no bearer post-pair fallthrough.
	denied := []tc{
		{http.MethodPost, "/pair/start", false},
		{http.MethodPost, "/pair/claim", false},
		{http.MethodPost, "/pair/psk-claim", false},
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

func TestFunnelBootstrapRejectsUnboundedBodiesBeforeUpstream(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream: upstreamURL,
		Mode:     ExposureModeFunnelBootstrap,
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name          string
		body          string
		contentLength int64
		transfer      []string
		wantStatus    int
	}{
		{name: "missing content length", body: "{}", contentLength: 0, wantStatus: http.StatusLengthRequired},
		{name: "chunked body", body: "{}", contentLength: -1, transfer: []string{"chunked"}, wantStatus: http.StatusLengthRequired},
		{name: "declared oversized", body: "{}", contentLength: prePairMaxBodyBytes + 1, wantStatus: http.StatusRequestEntityTooLarge},
		{
			name:          "actual body exceeds declared length",
			body:          strings.Repeat("x", int(prePairMaxBodyBytes)+1),
			contentLength: 2,
			wantStatus:    http.StatusRequestEntityTooLarge,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			upstreamHits = 0
			req := httptest.NewRequest(
				http.MethodPost,
				"/pair/psk-claim-v2",
				strings.NewReader(test.body),
			)
			req.ContentLength = test.contentLength
			req.TransferEncoding = test.transfer
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != test.wantStatus {
				t.Fatalf("got %d, want %d", rec.Code, test.wantStatus)
			}
			if upstreamHits != 0 {
				t.Fatalf("upstream received %d request(s), want 0", upstreamHits)
			}
		})
	}
}

func TestFunnelBootstrapRejectsBodiesOnPublicGetRoutes(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream: upstreamURL,
		Mode:     ExposureModeFunnelBootstrap,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/health", "/manifest", "/readyz"} {
		for _, contentLength := range []int64{-1, 1} {
			req := httptest.NewRequest(http.MethodGet, path, strings.NewReader("x"))
			req.ContentLength = contentLength
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s with content length %d got %d, want 413", path, contentLength, rec.Code)
			}
		}
	}
	if upstreamHits != 0 {
		t.Fatalf("upstream received %d request(s), want 0", upstreamHits)
	}
}

// TestFunnelBootstrapIsStrictSubsetOfPrePair asserts the funnel set never admits
// a path the pre-pair set denies, and is strictly smaller because it excludes
// /routez. This guards against the funnel mode drifting wider than pre-pair.
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
		if !strings.Contains(body, `"pairing_activation_contracts":["pairling.psk.activate.v1"]`) {
			t.Errorf("%s response missing activation contract: %s", path, body)
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

func TestFunnelLimiterDeniedUniqueIDsDoNotGrowState(t *testing.T) {
	limiter := NewFunnelLimiter(1, 100, 1)
	if !limiter.Allow("accepted") {
		t.Fatal("first request should consume the global budget")
	}

	for i := 0; i < 5000; i++ {
		if limiter.Allow(fmt.Sprintf("denied-%d", i)) {
			t.Fatalf("request %d passed after the global budget was exhausted", i)
		}
	}

	limiter.mu.Lock()
	entries := len(limiter.perPair)
	limiter.mu.Unlock()
	if entries != 1 {
		t.Fatalf("per-pair state entries = %d, want only the accepted identity", entries)
	}
}

func TestFunnelActivationDoesNotConsumeECDHLimiter(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	limiter := NewFunnelLimiter(100, 10, 1)
	handler, err := NewHandler(Options{
		Upstream:      upstreamURL,
		Mode:          ExposureModeFunnelBootstrap,
		FunnelLimiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := func(path, pairID string) int {
		req := httptest.NewRequest(
			http.MethodPost,
			path,
			strings.NewReader(`{"pair_id":"`+pairID+`"}`),
		)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if status := request("/pair/psk-claim-v2", "pairA"); status != http.StatusOK {
		t.Fatalf("first claim status = %d, want 200", status)
	}
	for i := 0; i < 4; i++ {
		if status := request("/pair/psk-activate", "pairA"); status != http.StatusOK {
			t.Fatalf("activation retry %d status = %d, want 200", i+1, status)
		}
	}
	release, ok := limiter.Acquire("occupied")
	if !ok {
		t.Fatal("failed to occupy the only ECDH slot")
	}
	defer release()
	if status := request("/pair/psk-activate", "pairB"); status != http.StatusOK {
		t.Fatalf("activation while ECDH is full status = %d, want 200", status)
	}
	if upstreamCalls != 6 {
		t.Fatalf("upstream calls = %d, want 6", upstreamCalls)
	}
}

func TestFunnelActivationHasIdentityIndependentGlobalLimit(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := NewHandler(Options{
		Upstream:      upstreamURL,
		Mode:          ExposureModeFunnelBootstrap,
		FunnelLimiter: NewFunnelLimiter(2, 100, 100),
	})
	if err != nil {
		t.Fatal(err)
	}

	request := func(pairID string) int {
		req := httptest.NewRequest(
			http.MethodPost,
			"/pair/psk-activate",
			strings.NewReader(`{"pair_id":"`+pairID+`"}`),
		)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if status := request("random-a"); status != http.StatusOK {
		t.Fatalf("first activation status = %d, want 200", status)
	}
	if status := request("random-b"); status != http.StatusOK {
		t.Fatalf("second activation status = %d, want 200", status)
	}
	if status := request("random-c"); status != http.StatusTooManyRequests {
		t.Fatalf("third unique activation status = %d, want 429", status)
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream calls = %d, want 2", upstreamCalls)
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
	req := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", strings.NewReader(`{"pair_id":"p"}`))
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

type funnelAdmissionTestBody struct {
	data    []byte
	reads   int
	entered chan struct{}
	proceed chan struct{}
	readErr error
}

func (b *funnelAdmissionTestBody) Read(dst []byte) (int, error) {
	b.reads++
	if b.entered != nil {
		close(b.entered)
		b.entered = nil
		<-b.proceed
	}
	if b.readErr != nil {
		return 0, b.readErr
	}
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(dst, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *funnelAdmissionTestBody) Close() error {
	return nil
}

func newFunnelAdmissionTestHandler(t *testing.T, mode ExposureMode, limiter *FunnelLimiter) *Handler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream:      upstreamURL,
		Mode:          mode,
		FunnelLimiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.funnelAdmission = make(chan struct{}, 1)
	return handler
}

func TestFunnelBodyAdmissionBudgetIsSharedAcrossHandlers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewHandler(Options{Upstream: upstreamURL, Mode: ExposureModeFunnelBootstrap})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewHandler(Options{Upstream: upstreamURL, Mode: ExposureModeFunnelBootstrap})
	if err != nil {
		t.Fatal(err)
	}
	if first.funnelAdmission != second.funnelAdmission {
		t.Fatal("Funnel handlers have independent pre-body budgets, want one process-global budget")
	}
}

func TestFunnelBodyAdmissionRejectsBeforeReadingWhenSaturated(t *testing.T) {
	handler := newFunnelAdmissionTestHandler(t, ExposureModeFunnelBootstrap, nil)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	firstBody := &funnelAdmissionTestBody{
		data:    []byte(`{"pair_id":"first"}`),
		entered: entered,
		proceed: proceed,
	}
	firstRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", firstBody)
	firstRequest.ContentLength = int64(len(firstBody.data))
	firstResponse := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(firstResponse, firstRequest)
		close(firstDone)
	}()

	<-entered
	secondBody := &funnelAdmissionTestBody{data: []byte(`{"pair_id":"second"}`)}
	secondRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", secondBody)
	secondRequest.ContentLength = int64(len(secondBody.data))
	secondResponse := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(secondResponse, secondRequest)
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		close(proceed)
		<-firstDone
		<-secondDone
		t.Fatal("saturated admission blocked instead of rejecting immediately")
	}

	close(proceed)
	<-firstDone
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated admission status = %d, want 429", secondResponse.Code)
	}
	if secondBody.reads != 0 {
		t.Fatalf("saturated request body reads = %d, want 0", secondBody.reads)
	}
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("admitted request status = %d, want 200", firstResponse.Code)
	}
}

func TestFunnelBodyAdmissionRecoversAfterMalformedAndSuccessfulRequests(t *testing.T) {
	handler := newFunnelAdmissionTestHandler(t, ExposureModeFunnelBootstrap, nil)
	malformedBody := &funnelAdmissionTestBody{readErr: io.ErrUnexpectedEOF}
	malformedRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", malformedBody)
	malformedRequest.ContentLength = 1
	malformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(malformedResponse, malformedRequest)
	if malformedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("malformed request status = %d, want 413", malformedResponse.Code)
	}

	for i := range 2 {
		body := &funnelAdmissionTestBody{data: []byte(fmt.Sprintf(`{"pair_id":"success-%d"}`, i))}
		request := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", body)
		request.ContentLength = int64(len(body.data))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("successful request %d status = %d, want 200", i+1, response.Code)
		}
	}
}

func TestFunnelBodyAdmissionIsDistinctFromParsedRequestLimits(t *testing.T) {
	limiter := NewFunnelLimiter(1, 1, 1)
	handler := newFunnelAdmissionTestHandler(t, ExposureModeFunnelBootstrap, limiter)
	handler.funnelAdmission <- struct{}{}

	deniedBody := &funnelAdmissionTestBody{data: []byte(`{"pair_id":"denied"}`)}
	deniedRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", deniedBody)
	deniedRequest.ContentLength = int64(len(deniedBody.data))
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, deniedRequest)
	if deniedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("pre-body denial status = %d, want 429", deniedResponse.Code)
	}
	if deniedBody.reads != 0 {
		t.Fatalf("pre-body denied request reads = %d, want 0", deniedBody.reads)
	}
	<-handler.funnelAdmission

	acceptedBody := &funnelAdmissionTestBody{data: []byte(`{"pair_id":"accepted"}`)}
	acceptedRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", acceptedBody)
	acceptedRequest.ContentLength = int64(len(acceptedBody.data))
	acceptedResponse := httptest.NewRecorder()
	handler.ServeHTTP(acceptedResponse, acceptedRequest)
	if acceptedResponse.Code != http.StatusOK {
		t.Fatalf("first parsed request status = %d, want 200", acceptedResponse.Code)
	}

	postParseDeniedBody := &funnelAdmissionTestBody{data: []byte(`{"pair_id":"other"}`)}
	postParseDeniedRequest := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", postParseDeniedBody)
	postParseDeniedRequest.ContentLength = int64(len(postParseDeniedBody.data))
	postParseDeniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(postParseDeniedResponse, postParseDeniedRequest)
	if postParseDeniedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("post-parse limiter status = %d, want 429", postParseDeniedResponse.Code)
	}
	if postParseDeniedBody.reads == 0 {
		t.Fatal("post-parse limiter rejected before body parsing; admission and parsed-request limits are not distinct")
	}
}

func TestFunnelBodyAdmissionDoesNotGatePrivateHandlers(t *testing.T) {
	handler := newFunnelAdmissionTestHandler(t, ExposureModePrePair, nil)
	handler.funnelAdmission <- struct{}{}
	defer func() { <-handler.funnelAdmission }()

	body := &funnelAdmissionTestBody{data: []byte(`{"pair_id":"private"}`)}
	request := httptest.NewRequest(http.MethodPost, "/pair/psk-claim-v2", body)
	request.ContentLength = int64(len(body.data))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("private handler status = %d, want 200", response.Code)
	}
	if body.reads == 0 {
		t.Fatal("private handler did not read the body")
	}
}
