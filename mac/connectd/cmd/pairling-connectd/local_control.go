package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dev.pairling/connectd/internal/gateway"
	"dev.pairling/connectd/internal/status"
)

const (
	controlRequestBodyLimit = int64(64 * 1024)
	controlMaxHeaderBytes   = 16 * 1024
)

type peerAuthorizingUnixListener struct {
	*net.UnixListener
	authorize func(*net.UnixConn) bool
}

func (l *peerAuthorizingUnixListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if l.authorize != nil && l.authorize(connection) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

type unixControlServer struct {
	server   *http.Server
	listener *net.UnixListener
	path     string
	identity os.FileInfo
	close    sync.Once
}

func startUnixControlServer(path string, store *status.Store, opener ...*authOpenGate) (*unixControlServer, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return nil, errors.New("connectd control socket path must be absolute")
	}
	if err := prepareUnixControlSocketPath(path); err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		cleanup()
		return nil, err
	}
	identity, err := os.Lstat(path)
	if err != nil || identity.Mode()&os.ModeSocket == 0 {
		cleanup()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("connectd control socket was not created as a socket")
	}

	authOpener := newAuthOpenGate()
	if len(opener) > 0 && opener[0] != nil {
		authOpener = opener[0]
	}
	server := &http.Server{
		Addr:              path,
		Handler:           newUnixControlHandler(store, authOpener),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    controlMaxHeaderBytes,
	}
	wrapped := &peerAuthorizingUnixListener{
		UnixListener: listener,
		authorize:    sameUIDPeer,
	}
	control := &unixControlServer{
		server:   server,
		listener: listener,
		path:     path,
		identity: identity,
	}
	go func() {
		if err := server.Serve(wrapped); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("control server stopped: %v", err)
			store.SetLastError("local control server stopped")
		}
	}()
	return control, nil
}

func prepareUnixControlSocketPath(path string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("connectd control socket parent is not a directory: %s", parent)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket control path: %s", path)
	}
	probe, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
	if dialErr == nil {
		_ = probe.Close()
		return fmt.Errorf("connectd control socket is already active: %s", path)
	}
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return nil
}

func newUnixControlHandler(store *status.Store, opener *authOpenGate) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/status", store.Handler())
	mux.HandleFunc("/auth/open", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(writer, "POST required", http.StatusMethodNotAllowed)
			return
		}
		writeAuthOpenResponse(writer, store, opener)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if len(request.TransferEncoding) != 0 || request.ContentLength < 0 {
			http.Error(writer, "bounded Content-Length required", http.StatusLengthRequired)
			return
		}
		if request.ContentLength > controlRequestBodyLimit {
			http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if request.ContentLength != 0 {
			http.Error(writer, "request body must be empty", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func probePairlingRoute(ctx context.Context, socketPath string, store *status.Store) bool {
	transport := &http.Transport{
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(dialContext, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://localhost/routez",
		nil,
	)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	valid := err == nil &&
		len(body) <= 64<<10 &&
		response.StatusCode >= 200 &&
		response.StatusCode < 400 &&
		gateway.RouteResponseIsValid(body)
	if valid {
		store.RecordGatewayEvent(http.MethodGet, "/routez", response.StatusCode, "route_verified")
	}
	return valid
}


func (s *unixControlServer) Close() {
	if s == nil {
		return
	}
	s.close.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
		_ = s.listener.Close()
		current, err := os.Lstat(s.path)
		if err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(s.identity, current) {
			_ = os.Remove(s.path)
		}
	})
}
