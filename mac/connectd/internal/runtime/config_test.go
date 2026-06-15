package runtime

import (
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
