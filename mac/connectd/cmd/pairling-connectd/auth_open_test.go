package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dev.pairling/connectd/internal/status"
)

func TestAuthOpenEndpointOpensStoredURLWithoutReturningIt(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	rawAuthURL := "https://login.tailscale.com/a/secret-auth-token?next=pairling"
	store.SetAuthPending("approve at " + rawAuthURL)

	originalOpenAuthURL := openAuthURL
	defer func() { openAuthURL = originalOpenAuthURL }()
	var openedURL string
	openAuthURL = func(rawURL string) error {
		openedURL = rawURL
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store)

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
}

func TestAuthOpenEndpointRequiresLoopbackAndPost(t *testing.T) {
	store := status.NewStore("pairling-inst-test")
	store.SetAuthPending("approve at https://login.tailscale.com/a/example-token")

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
			handleAuthOpen(rec, req, store)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestAuthOpenEndpointReturnsSafeUnavailableError(t *testing.T) {
	store := status.NewStore("pairling-inst-test")

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store)

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

	originalOpenAuthURL := openAuthURL
	defer func() { openAuthURL = originalOpenAuthURL }()
	opened := false
	openAuthURL = func(rawURL string) error {
		opened = true
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/open", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handleAuthOpen(rec, req, store)

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
