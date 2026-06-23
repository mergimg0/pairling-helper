package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStateDirUsesPairlingApplicationSupport(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "example")
	got := DefaultStateDir(home)
	want := filepath.Join(home, "Library", "Application Support", "Pairling", "connectd", "tsnet-state")
	if got != want {
		t.Fatalf("state dir = %q, want %q", got, want)
	}
}

func TestHostnameFromInstallIDIsPairlingScopedAndStable(t *testing.T) {
	got := HostnameFromInstallID("inst_abcDEF-1234567890")
	if got != "pairling-inst-abcdef" {
		t.Fatalf("hostname = %q", got)
	}
}

func TestHostnameFromInstallIDFallsBackWhenInstallIDMissing(t *testing.T) {
	got := HostnameFromInstallID("")
	if got == "" || got == "pairling-" {
		t.Fatalf("hostname fallback is empty: %q", got)
	}
}

func TestStableHostnamePersistsAcrossInstallIDChange(t *testing.T) {
	dir := t.TempDir()
	appSupport := filepath.Join(dir, "appsupport")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(appSupport, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appSupport, "config.json"), []byte(`{"install_id":"inst_first123"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first := StableHostname(appSupport, stateDir)
	if first == "" || first == "pairling-" {
		t.Fatalf("first hostname empty: %q", first)
	}
	// Simulated reinstall: install_id changes, but the persisted hostname must win.
	if err := os.WriteFile(filepath.Join(appSupport, "config.json"), []byte(`{"install_id":"inst_second999"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second := StableHostname(appSupport, stateDir)
	if second != first {
		t.Fatalf("hostname changed after install_id change: %q -> %q", first, second)
	}
}
