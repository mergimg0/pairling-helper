package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"dev.pairling/connectd/internal/status"
)

func shortUnixSocketPath(t *testing.T, pattern string) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	} else {
		var err error
		base, err = filepath.EvalSymlinks(base)
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.MkdirTemp(base, "pairling-socket-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	return filepath.Join(root, pattern+".sock")
}


func TestPeerAuthorizingUnixListenerDropsUnauthorizedConnection(t *testing.T) {
	path := shortUnixSocketPath(t, "pairling-peer")
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	var attempts atomic.Int32
	listener := &peerAuthorizingUnixListener{
		UnixListener: raw,
		authorize: func(*net.UnixConn) bool {
			return attempts.Add(1) > 1
		},
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	unauthorized, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.SetReadDeadline(time.Now().Add(time.Second))
	if _, writeErr := unauthorized.Write([]byte("must not dispatch")); writeErr == nil {
		buffer := make([]byte, 1)
		if count, readErr := unauthorized.Read(buffer); count != 0 || readErr == nil {
			t.Fatalf("unauthorized peer remained open: count=%d error=%v", count, readErr)
		}
	}
	_ = unauthorized.Close()
	select {
	case connection := <-accepted:
		_ = connection.Close()
		t.Fatal("unauthorized peer reached dispatch")
	default:
	}

	authorized, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer authorized.Close()
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("authorized peer was not accepted")
	}
}

func TestPairlingRouteProbeUsesUnixSocketWithoutInternalToken(t *testing.T) {
	path := shortUnixSocketPath(t, "pairling-route")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	var tokenExposed atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Pairling-Internal-Token") != "" {
			tokenExposed.Store(true)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true,"schema_version":1,"contract_version":"pairling-runtime-v1","runtime":{"verified":true,"contract_version":"pairling-runtime-v1"}}`)
	})}
	go func() {
		_ = server.Serve(listener)
	}()

	store := status.NewStore("pairling-test")
	for range status.GatewayRecoveryProofs {
		if !probePairlingRoute(context.Background(), path, store) {
			t.Fatal("same-UID Unix route proof failed")
		}
	}
	if !store.Snapshot().GatewayHealthy {
		t.Fatal("verified Unix route proofs did not recover gateway health")
	}
	if tokenExposed.Load() {
		t.Fatal("route probe exposed internal token")
	}
	_ = server.Shutdown(context.Background())
	_ = listener.Close()
}


func TestConnectdControlServerIsPrivateBoundedAndCleanupSafe(t *testing.T) {
	path := shortUnixSocketPath(t, "pairling-control")
	store := status.NewStore("pairling-test")
	server, err := startUnixControlServer(path, store)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	if _, err := startUnixControlServer(path, store); err == nil {
		t.Fatal("second server replaced a live control socket")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("http://localhost/status")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("status = %d body = %q", response.StatusCode, body)
	}

	request, err := http.NewRequest(http.MethodPost, "http://localhost/auth/open", io.LimitReader(zeroReader{}, controlRequestBodyLimit+1))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = controlRequestBodyLimit + 1
	oversized, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = oversized.Body.Close()
	if oversized.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want %d", oversized.StatusCode, http.StatusRequestEntityTooLarge)
	}

	server.Close()
	transport.CloseIdleConnections()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("control socket survived close: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(blocker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startUnixControlServer(blocker, store); err == nil {
		t.Fatal("regular file was replaced by control socket")
	}
	if body, err := os.ReadFile(blocker); err != nil || string(body) != "preserve" {
		t.Fatalf("regular file changed: body=%q error=%v", body, err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}
