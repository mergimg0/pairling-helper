package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAuthKeyTag(t *testing.T) {
	t.Setenv("PAIRLING_TS_AUTHKEY_TAG", "")
	if got := defaultAuthKeyTag(); got != "tag:pairling-connect" {
		t.Fatalf("default tag = %q, want tag:pairling-connect", got)
	}
	t.Setenv("PAIRLING_TS_AUTHKEY_TAG", "tag:custom")
	if got := defaultAuthKeyTag(); got != "tag:custom" {
		t.Fatalf("override tag = %q, want tag:custom", got)
	}
}

func TestLoadTailscaleAuthKeyPrefersEnv(t *testing.T) {
	dir := t.TempDir()
	connectdDir := filepath.Join(dir, "connectd")
	if err := os.MkdirAll(connectdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(connectdDir, "connectd-ts-authkey"), []byte("tskey-auth-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PAIRLING_TS_AUTHKEY", "  tskey-auth-from-env  ")
	if got := loadTailscaleAuthKey(dir); got != "tskey-auth-from-env" {
		t.Fatalf("env precedence failed: got %q", got)
	}

	t.Setenv("PAIRLING_TS_AUTHKEY", "")
	if got := loadTailscaleAuthKey(dir); got != "tskey-auth-from-file" {
		t.Fatalf("file fallback failed: got %q", got)
	}
}

func TestLoadTailscaleAuthKeyAbsentIsInteractive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PAIRLING_TS_AUTHKEY", "")
	if got := loadTailscaleAuthKey(dir); got != "" {
		t.Fatalf("expected empty (interactive) when no key present, got %q", got)
	}
}
