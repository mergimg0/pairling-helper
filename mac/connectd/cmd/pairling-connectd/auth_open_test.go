package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev.pairling/connectd/internal/status"
)

type fakeAuthOpenProcess struct {
	waited bool
}

func (p *fakeAuthOpenProcess) Wait() error {
	p.waited = true
	return nil
}

func testAuthOpenGate(
	t *testing.T,
	starter authOpenStarter,
	now func() time.Time,
) (*authOpenGate, chan func()) {
	t.Helper()
	workers := make(chan func(), 128)
	if now == nil {
		now = time.Now
	}
	return &authOpenGate{
		retryCooldown: authOpenRetryCooldown,
		now:           now,
		start:         starter,
		runWorker: func(work func()) {
			workers <- work
		},
	}, workers
}

func TestAuthOpenEndpointOpensStoredURLWithoutReturningIt(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	rawAuthURL := "https://login.tailscale.com/a/secret-auth-token?next=pairling"
	store.SetAuthPending("approve at " + rawAuthURL)

	process := &fakeAuthOpenProcess{}
	var openedURL string
	gate, workers := testAuthOpenGate(t, func(rawURL string) (authOpenProcess, error) {
		openedURL = rawURL
		return process, nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store, gate)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if openedURL != rawAuthURL {
		t.Fatalf("opened URL = %q, want raw in-memory auth URL", openedURL)
	}
	if strings.Contains(rec.Body.String(), "secret-auth-token") || strings.Contains(rec.Body.String(), "login.tailscale.com/a/") {
		t.Fatalf("auth/open response leaked auth URL: %s", rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true || body["opened"] != true || body["auth_url_present"] != true {
		t.Fatalf("bad auth/open response: %+v", body)
	}
	if len(workers) != 1 {
		t.Fatalf("reaper workers = %d, want 1", len(workers))
	}
	(<-workers)()
	if !process.waited {
		t.Fatal("opened child process was not waited")
	}
}

func TestAuthOpenEndpointRequiresLoopbackAndPost(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at https://login.tailscale.com/a/example-token")
	gate, _ := testAuthOpenGate(t, func(string) (authOpenProcess, error) {
		t.Fatal("rejected request started an auth-open child")
		return nil, nil
	}, nil)

	for _, tc := range []struct {
		name       string
		method     string
		remoteAddr string
		wantStatus int
	}{
		{name: "get denied", method: http.MethodGet, remoteAddr: "127.0.0.1:54321", wantStatus: http.StatusMethodNotAllowed},
		{name: "non loopback denied", method: http.MethodPost, remoteAddr: "192.0.2.10:54321", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/auth/open", nil)
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			handleAuthOpen(rec, req, store, gate)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestAuthOpenEndpointReturnsSafeUnavailableError(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	gate, _ := testAuthOpenGate(t, func(string) (authOpenProcess, error) {
		t.Fatal("unavailable auth URL started a child")
		return nil, nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store, gate)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "login.tailscale.com/a/") {
		t.Fatalf("unavailable response leaked auth URL: %s", rec.Body.String())
	}
}

func TestAuthOpenEndpointDoesNotOpenInvalidAuthURL(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at http://login.tailscale.com/a/not-secure")

	opened := false
	gate, _ := testAuthOpenGate(t, func(string) (authOpenProcess, error) {
		opened = true
		return &fakeAuthOpenProcess{}, nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store, gate)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if opened {
		t.Fatal("invalid auth URL was opened")
	}
	if strings.Contains(rec.Body.String(), "not-secure") || strings.Contains(rec.Body.String(), "login.tailscale.com/a/") {
		t.Fatalf("invalid URL response leaked auth URL: %s", rec.Body.String())
	}
}

func TestAuthOpenEndpointBoundsConcurrentAndCooldownRetries(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at https://login.tailscale.com/a/same-token")
	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	var startsMu sync.Mutex
	processes := make([]*fakeAuthOpenProcess, 0, 2)
	gate, workers := testAuthOpenGate(t, func(string) (authOpenProcess, error) {
		startsMu.Lock()
		defer startsMu.Unlock()
		process := &fakeAuthOpenProcess{}
		processes = append(processes, process)
		return process, nil
	}, clock)

	const requestCount = 32
	var requests sync.WaitGroup
	requests.Add(requestCount)
	for range requestCount {
		go func() {
			defer requests.Done()
			req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			handleAuthOpen(httptest.NewRecorder(), req, store, gate)
		}()
	}
	requests.Wait()

	startsMu.Lock()
	startCount := len(processes)
	startsMu.Unlock()
	if startCount != 1 || len(workers) != 1 {
		t.Fatalf("concurrent requests started %d children and %d reapers, want 1 each", startCount, len(workers))
	}
	(<-workers)()
	if !processes[0].waited {
		t.Fatal("admitted child completion was not reaped")
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store, gate)
	if rec.Code != http.StatusOK {
		t.Fatalf("cooldown response status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true || body["opened"] != false {
		t.Fatalf("cooldown response = %+v, want idempotent suppression", body)
	}
	startsMu.Lock()
	startCount = len(processes)
	startsMu.Unlock()
	if startCount != 1 {
		t.Fatalf("same URL retried before cooldown: starts = %d", startCount)
	}

	nowMu.Lock()
	now = now.Add(authOpenRetryCooldown)
	nowMu.Unlock()
	rec = httptest.NewRecorder()
	handleAuthOpen(rec, req, store, gate)
	startsMu.Lock()
	startCount = len(processes)
	startsMu.Unlock()
	if startCount != 2 || len(workers) != 1 {
		t.Fatalf("cooldown retry started %d children and left %d reapers, want 2 starts and 1 queued reaper", startCount, len(workers))
	}
	(<-workers)()
}

func TestAuthOpenEndpointAllowsNewURLAfterChildIsReaped(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	firstURL := "https://login.tailscale.com/a/first-token"
	secondURL := "https://login.tailscale.com/a/second-token"
	store.SetAuthPending("approve at " + firstURL)
	openedURLs := make([]string, 0, 2)
	gate, workers := testAuthOpenGate(t, func(rawURL string) (authOpenProcess, error) {
		openedURLs = append(openedURLs, rawURL)
		return &fakeAuthOpenProcess{}, nil
	}, nil)

	open := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		handleAuthOpen(rec, req, store, gate)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		(<-workers)()
	}
	open()
	store.SetAuthPending("approve at " + secondURL)
	open()

	if len(openedURLs) != 2 || openedURLs[0] != firstURL || openedURLs[1] != secondURL {
		t.Fatalf("opened URLs = %q, want [%q %q]", openedURLs, firstURL, secondURL)
	}
}

func TestAuthOpenEndpointStartFailureRetriesOnlyAfterCooldown(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at https://login.tailscale.com/a/retry-token")
	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	starts := 0
	gate, _ := testAuthOpenGate(t, func(string) (authOpenProcess, error) {
		starts++
		return nil, errors.New("start failed")
	}, func() time.Time { return now })
	request := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		handleAuthOpen(rec, req, store, gate)
		return rec
	}

	if rec := request(); rec.Code != http.StatusInternalServerError {
		t.Fatalf("initial start failure status = %d, want 500", rec.Code)
	}
	if rec := request(); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cooldown suppression status = %d, want 503", rec.Code)
	}
	if starts != 1 {
		t.Fatalf("start failures before cooldown = %d, want 1", starts)
	}
	now = now.Add(authOpenRetryCooldown)
	if rec := request(); rec.Code != http.StatusInternalServerError {
		t.Fatalf("retry failure status = %d, want 500", rec.Code)
	}
	if starts != 2 {
		t.Fatalf("starts after cooldown = %d, want 2", starts)
	}
}

func TestStatusEndpointRequiresLoopbackInternalToken(t *testing.T) {
	home := t.TempDir()
	tokenDir := filepath.Join(home, ".claude", "companion")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(tokenDir, "internal-hook-token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	handler := requireInternalStatusToken(home, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name       string
		remoteAddr string
		token      string
		wantStatus int
	}{
		{name: "missing token", remoteAddr: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", remoteAddr: "127.0.0.1:54321", token: strings.Repeat("b", 64), wantStatus: http.StatusUnauthorized},
		{name: "non loopback", remoteAddr: "192.0.2.10:54321", token: token, wantStatus: http.StatusForbidden},
		{name: "authorized", remoteAddr: "[::1]:54321", token: token, wantStatus: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/status", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.token != "" {
				req.Header.Set(internalStatusTokenHeader, tc.token)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}

	missingSecret := requireInternalStatusToken(t.TempDir(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran without an internal token")
	}))
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	missingSecret.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing-secret status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestStatusServerRequiresInternalTokenForEveryRoute(t *testing.T) {
	home := t.TempDir()
	tokenDir := filepath.Join(home, ".claude", "companion")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(tokenDir, "internal-hook-token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at https://login.tailscale.com/a/example-token")
	handler := newStatusHandler(home, store)
	for _, route := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/status"},
		{method: http.MethodGet, path: "/healthz"},
		{method: http.MethodPost, path: "/auth/open"},
	} {
		req := httptest.NewRequest(route.method, route.path, nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want %d", route.method, route.path, rec.Code, http.StatusUnauthorized)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "[::1]:54321"
	req.Header.Set(internalStatusTokenHeader, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
}
