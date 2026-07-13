package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"dev.pairling/connectd/internal/status"
)

func TestCheckUpstreamUsesCheapReadyzEndpoint(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/readyz" {
			http.Error(w, "expensive health path called", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"contract_version":"pairling-runtime-v1"}`))
	}))
	defer server.Close()

	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if !checkUpstream(upstream) {
		t.Fatal("checkUpstream returned false for readyz success")
	}
	if gotPath != "/readyz" {
		t.Fatalf("checkUpstream path = %q, want /readyz", gotPath)
	}
}

func TestCheckUpstreamRejectsNonSemanticReadyzResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "no content", status: http.StatusNoContent},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"ok":true,"contract_version":"pairling-runtime-v1"}`},
		{name: "not found", status: http.StatusNotFound, body: `{"ok":true,"contract_version":"pairling-runtime-v1"}`},
		{name: "invalid json", status: http.StatusOK, body: `{`},
		{name: "not ready", status: http.StatusOK, body: `{"ok":false,"contract_version":"pairling-runtime-v1"}`},
		{name: "wrong contract", status: http.StatusOK, body: `{"ok":true,"contract_version":"legacy-runtime-v1"}`},
		{name: "missing contract", status: http.StatusOK, body: `{"ok":true}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			upstream, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}

			if checkUpstream(upstream) {
				t.Fatalf("checkUpstream accepted status=%d body=%q", test.status, test.body)
			}
		})
	}
}

func TestRefreshUpstreamStatusAutonomouslyRecoversThroughGatewayProofs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":true,"contract_version":"pairling-runtime-v1"}`)
	}))
	defer server.Close()
	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := status.NewStore("pairling-test")
	store.SetUpstreamReachable(true)
	store.RecordGatewayEvent("GET", "/routez", http.StatusBadGateway, "upstream_error")
	var calls int

	refreshUpstreamStatus(context.Background(), upstream, store, func(context.Context) bool {
		calls++
		store.RecordGatewayEvent("GET", "/routez", http.StatusOK, "route_verified")
		return true
	})

	if calls != status.GatewayRecoveryProofs {
		t.Fatalf("route probe calls = %d, want %d", calls, status.GatewayRecoveryProofs)
	}
	if !store.Snapshot().GatewayHealthy {
		t.Fatal("gateway did not recover after consecutive semantic proofs")
	}
}

func TestRefreshUpstreamStatusDoesNotOpenCleanStartupFromReadyzAlone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":true,"contract_version":"pairling-runtime-v1"}`)
	}))
	defer server.Close()
	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := status.NewStore("pairling-test")

	refreshUpstreamStatus(context.Background(), upstream, store, nil)

	snapshot := store.Snapshot()
	if !snapshot.UpstreamReachable {
		t.Fatal("semantic readyz response should mark the upstream reachable")
	}
	if snapshot.GatewayHealthy || len(snapshot.AdvertisedRoutes) != 0 {
		t.Fatalf("readyz alone opened an unverified route: %+v", snapshot)
	}
}

func TestRefreshUpstreamStatusRevalidatesAndClosesHealthyRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":true,"contract_version":"pairling-runtime-v1"}`)
	}))
	defer server.Close()
	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := status.NewStore("pairling-test")
	store.SetUpstreamReachable(true)
	for range status.GatewayRecoveryProofs {
		store.RecordGatewayEvent(http.MethodGet, "/routez", http.StatusOK, "route_verified")
	}
	var calls int

	refreshUpstreamStatus(context.Background(), upstream, store, func(context.Context) bool {
		calls++
		return false
	})

	if calls != 1 {
		t.Fatalf("healthy route probe calls = %d, want 1", calls)
	}
	if store.Snapshot().GatewayHealthy {
		t.Fatal("failed periodic /routez proof left the route healthy")
	}
}

func TestRefreshUpstreamStatusKeepsRouteFailedWhenProofFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":true,"contract_version":"pairling-runtime-v1"}`)
	}))
	defer server.Close()
	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := status.NewStore("pairling-test")
	store.SetUpstreamReachable(true)
	store.RecordGatewayEvent("GET", "/routez", http.StatusBadGateway, "upstream_error")
	var calls int

	refreshUpstreamStatus(context.Background(), upstream, store, func(context.Context) bool {
		calls++
		return false
	})

	if calls != 1 {
		t.Fatalf("route probe calls = %d, want 1", calls)
	}
	if store.Snapshot().GatewayHealthy {
		t.Fatal("failed semantic proof recovered the route")
	}
}

func TestLoadInternalHookTokenRequiresExactHexToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "internal-hook-token")
	t.Setenv("PAIRLING_INTERNAL_HOOK_TOKEN_FILE", path)
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(valid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadInternalHookToken(t.TempDir()); got != valid {
		t.Fatalf("token = %q, want valid token", got)
	}
	if err := os.WriteFile(path, []byte("not-a-valid-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadInternalHookToken(t.TempDir()); got != "" {
		t.Fatalf("invalid token accepted: %q", got)
	}
}
