package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"dev.pairling/connectd/internal/status"
)

func TestWriteBuildInfoUsesLinkerStamps(t *testing.T) {
	originalVersion := buildVersion
	originalRevision := buildSourceRevision
	originalDirty := buildSourceDirty
	t.Cleanup(func() {
		buildVersion = originalVersion
		buildSourceRevision = originalRevision
		buildSourceDirty = originalDirty
	})

	buildVersion = "1.2.3"
	buildSourceRevision = "0123456789abcdef0123456789abcdef01234567"
	buildSourceDirty = "false"

	var output bytes.Buffer
	if err := writeBuildInfo(&output); err != nil {
		t.Fatalf("writeBuildInfo: %v", err)
	}
	var got buildInfo
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode build info: %v", err)
	}
	if got.SchemaVersion != 1 || got.Version != buildVersion ||
		got.SourceRevision != buildSourceRevision || got.SourceDirty {
		t.Fatalf("unexpected build info: %+v", got)
	}
}

func TestCurrentBuildInfoRejectsInvalidDirtyStamp(t *testing.T) {
	original := buildSourceDirty
	t.Cleanup(func() { buildSourceDirty = original })
	buildSourceDirty = "not-a-boolean"
	if _, err := currentBuildInfo(); err == nil {
		t.Fatal("expected invalid dirty stamp to fail")
	}
}

func TestStatusSnapshotUsesExactBuildIdentity(t *testing.T) {
	store := status.NewStore("pairling-test")
	store.SetBuildIdentity(
		os.Getpid(),
		"1.2.3",
		"0123456789abcdef0123456789abcdef01234567",
		false,
	)
	recorder := httptest.NewRecorder()
	store.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/status", nil))

	var got status.Snapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.PID != os.Getpid() || got.Version != "1.2.3" ||
		got.ConnectdVersion != "1.2.3" ||
		got.SourceRevision != "0123456789abcdef0123456789abcdef01234567" ||
		got.SourceDirty {
		t.Fatalf("unexpected status build identity: %+v", got)
	}
}

func TestRunFailsWhenStatusAddressIsOccupied(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve status address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	exitCode := run([]string{
		"--hostname", "pairling-test",
		"--state-dir", t.TempDir(),
		"--status-addr", listener.Addr().String(),
	})
	if exitCode != 1 {
		t.Fatalf("occupied status address exit code = %d, want 1", exitCode)
	}
}
