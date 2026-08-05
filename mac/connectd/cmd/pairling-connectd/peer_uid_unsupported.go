//go:build !darwin && !linux

package main

import "net"

func sameUIDPeer(_ *net.UnixConn) bool {
	return false
}
