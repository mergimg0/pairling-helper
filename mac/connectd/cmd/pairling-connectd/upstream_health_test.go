package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCheckUpstreamUsesCheapReadyzEndpoint(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/readyz" {
			http.Error(w, "expensive health path called", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
