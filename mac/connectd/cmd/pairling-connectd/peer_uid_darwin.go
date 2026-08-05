//go:build darwin

package main

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func sameUIDPeer(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var peerUID uint32
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		peerUID = credentials.Uid
	}); err != nil || credentialErr != nil {
		return false
	}
	return peerUID == uint32(os.Getuid())
}
