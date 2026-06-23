package main

import (
	"context"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeWhoIsClient struct {
	addr string
	resp *apitype.WhoIsResponse
	err  error
}

func (f *fakeWhoIsClient) WhoIs(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	f.addr = remoteAddr
	return f.resp, f.err
}

func TestPeerNodeResolverUsesWhoIsRemoteAddr(t *testing.T) {
	fake := &fakeWhoIsClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				StableID: tailcfg.StableNodeID("nPeerCNTRL"),
				Tags:     []string{"tag:pairling-phone"},
			},
		},
	}
	resolver := tailscalePeerNodeResolver{
		localClient: func() (whoIsClient, error) {
			return fake, nil
		},
	}

	nodeID, ok := resolver.PeerNodeID(context.Background(), "100.64.0.50:12345")
	if !ok {
		t.Fatal("resolver should accept tagged peer")
	}
	if fake.addr != "100.64.0.50:12345" {
		t.Fatalf("WhoIs addr = %q", fake.addr)
	}
	if nodeID != "nPeerCNTRL" {
		t.Fatalf("node ID = %q", nodeID)
	}
}

func TestWhoIsResolvesPeerStableID(t *testing.T) {
	nodeID, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: tailcfg.StableNodeID("nPeerCNTRL"),
			Tags:     []string{"tag:pairling-phone"},
		},
	})

	if !ok {
		t.Fatal("WhoIs peer should resolve")
	}
	if nodeID != "nPeerCNTRL" {
		t.Fatalf("node ID = %q, want nPeerCNTRL", nodeID)
	}
}

func TestAssertsGrantedPhoneTagBeforePersist(t *testing.T) {
	cases := []struct {
		name string
		tags []string
	}{
		{name: "untagged"},
		{name: "wrong tag", tags: []string{"tag:pairling-connect"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodeID, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					StableID: tailcfg.StableNodeID("nPeerCNTRL"),
					Tags:     tc.tags,
				},
			})
			if ok || nodeID != "" {
				t.Fatalf("wrongly accepted node ID %q with tags %#v", nodeID, tc.tags)
			}
		})
	}
}
