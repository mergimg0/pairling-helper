package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFunnelBootstrapMatchesContract ties funnelBootstrapAllowed to the shared
// cross-language endpoint contract, so the funnel allowlist cannot drift from the
// source-of-truth list that the Swift and Python sides also read.
func TestFunnelBootstrapMatchesContract(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile),
		"..", "..", "..", "..", "thoughts", "shared", "contracts", "pairling-connect-endpoints.json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var contract struct {
		Rows []struct {
			Method                  string `json:"method"`
			SamplePath              string `json:"sample_path"`
			ConnectdFunnelBootstrap bool   `json:"connectd_funnel_bootstrap"`
			AssertFunnelParity      bool   `json:"assert_funnel_parity"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("parse contract: %v", err)
	}

	funnelTrueTotal := 0
	checked := 0
	for _, row := range contract.Rows {
		if row.ConnectdFunnelBootstrap {
			funnelTrueTotal++
		}
		if !row.AssertFunnelParity {
			continue
		}
		checked++
		got := funnelBootstrapAllowed(row.Method, row.SamplePath)
		if got != row.ConnectdFunnelBootstrap {
			t.Errorf("%s %s: funnelBootstrapAllowed=%v, contract connectd_funnel_bootstrap=%v",
				row.Method, row.SamplePath, got, row.ConnectdFunnelBootstrap)
		}
	}
	if checked == 0 {
		t.Fatal("no assert_funnel_parity rows found; the contract is not wired")
	}
	if funnelTrueTotal != 5 {
		t.Errorf("connectd_funnel_bootstrap true rows = %d, want exactly 5 (the funnel set)", funnelTrueTotal)
	}
}
