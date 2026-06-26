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

	nodeID, provenance, ok := resolver.PeerNodeID(context.Background(), "100.64.0.50:12345")
	if !ok {
		t.Fatal("resolver should accept tagged peer")
	}
	if fake.addr != "100.64.0.50:12345" {
		t.Fatalf("WhoIs addr = %q", fake.addr)
	}
	if nodeID != "nPeerCNTRL" {
		t.Fatalf("node ID = %q", nodeID)
	}
	if provenance != "tagged" {
		t.Fatalf("provenance = %q, want tagged", provenance)
	}
}

func TestWhoIsResolvesPeerStableID(t *testing.T) {
	nodeID, provenance, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
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
	if provenance != "tagged" {
		t.Fatalf("provenance = %q, want tagged", provenance)
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
			nodeID, provenance, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					StableID: tailcfg.StableNodeID("nPeerCNTRL"),
					Tags:     tc.tags,
				},
			})
			if ok || nodeID != "" || provenance != "" {
				t.Fatalf("wrongly accepted node ID %q provenance %q with tags %#v", nodeID, provenance, tc.tags)
			}
		})
	}
}

// TestPeerNodeIDProvenanceFromWhoIs covers the interactive-sign-in provenance
// path: an untagged, user-owned iOS node whose WhoIs hostname starts with
// pairling-ios- is admitted as "interactive", while a tagged phone is admitted
// as "tagged". Non-Pairling untagged nodes and OS-mismatched nodes are rejected.
func TestPeerNodeIDProvenanceFromWhoIs(t *testing.T) {
	cases := []struct {
		name           string
		node           *tailcfg.Node
		wantNodeID     string
		wantProvenance string
		wantOK         bool
	}{
		{
			name: "tagged phone",
			node: &tailcfg.Node{
				StableID: tailcfg.StableNodeID("nPeerCNTRL"),
				Tags:     []string{"tag:pairling-phone"},
			},
			wantNodeID:     "nPeerCNTRL",
			wantProvenance: "tagged",
			wantOK:         true,
		},
		{
			name: "untagged interactive ios computed name",
			node: &tailcfg.Node{
				StableID:     tailcfg.StableNodeID("nInteractiveIOS"),
				ComputedName: "pairling-ios-b702bb49",
			},
			wantNodeID:     "nInteractiveIOS",
			wantProvenance: "interactive",
			wantOK:         true,
		},
		{
			name: "untagged non-pairling laptop",
			node: &tailcfg.Node{
				StableID:     tailcfg.StableNodeID("nLaptop"),
				ComputedName: "my-laptop",
			},
			wantNodeID:     "",
			wantProvenance: "",
			wantOK:         false,
		},
		{
			name: "untagged pairling-ios prefix but macOS hostinfo rejected",
			node: &tailcfg.Node{
				StableID:     tailcfg.StableNodeID("nFakeIOS"),
				ComputedName: "pairling-ios-x",
				Hostinfo:     (&tailcfg.Hostinfo{OS: "macOS"}).View(),
			},
			wantNodeID:     "",
			wantProvenance: "",
			wantOK:         false,
		},
		{
			name: "empty stable id",
			node: &tailcfg.Node{
				StableID: tailcfg.StableNodeID(""),
				Tags:     []string{"tag:pairling-phone"},
			},
			wantNodeID:     "",
			wantProvenance: "",
			wantOK:         false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodeID, provenance, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{Node: tc.node})
			if ok != tc.wantOK {
				t.Fatalf("ok = %t, want %t (nodeID=%q provenance=%q)", ok, tc.wantOK, nodeID, provenance)
			}
			if nodeID != tc.wantNodeID {
				t.Fatalf("nodeID = %q, want %q", nodeID, tc.wantNodeID)
			}
			if provenance != tc.wantProvenance {
				t.Fatalf("provenance = %q, want %q", provenance, tc.wantProvenance)
			}
		})
	}
}

// TestPeerNodeIDInteractiveAcceptsIOSHostinfo confirms an untagged Pairling iOS
// node with Hostinfo OS reported as "iOS" (case-insensitive) is still admitted
// as interactive — the OS check only rejects a non-empty, non-iOS OS.
func TestPeerNodeIDInteractiveAcceptsIOSHostinfo(t *testing.T) {
	nodeID, provenance, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID:     tailcfg.StableNodeID("nIOS"),
			ComputedName: "pairling-ios-abc123",
			Hostinfo:     (&tailcfg.Hostinfo{OS: "iOS"}).View(),
		},
	})
	if !ok {
		t.Fatal("untagged pairling iOS node with iOS Hostinfo should be admitted")
	}
	if nodeID != "nIOS" {
		t.Fatalf("nodeID = %q, want nIOS", nodeID)
	}
	if provenance != "interactive" {
		t.Fatalf("provenance = %q, want interactive", provenance)
	}
}

// TestPeerNodeIDInteractiveFallsBackToHostinfoHostname confirms that when
// ComputedName is empty, the WhoIs hostname is derived from a valid Hostinfo's
// Hostname() and the pairling-ios- prefix is still honored.
func TestPeerNodeIDInteractiveFallsBackToHostinfoHostname(t *testing.T) {
	nodeID, provenance, ok := peerNodeIDFromWhoIs(&apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: tailcfg.StableNodeID("nIOSHost"),
			Hostinfo: (&tailcfg.Hostinfo{Hostname: "pairling-ios-fallback", OS: "iOS"}).View(),
		},
	})
	if !ok {
		t.Fatal("untagged pairling iOS node identified via Hostinfo hostname should be admitted")
	}
	if nodeID != "nIOSHost" {
		t.Fatalf("nodeID = %q, want nIOSHost", nodeID)
	}
	if provenance != "interactive" {
		t.Fatalf("provenance = %q, want interactive", provenance)
	}
}

// TestPeerNodeIDRejectsNilNode confirms a nil WhoIs or nil Node yields the
// empty-rejection tuple.
func TestPeerNodeIDRejectsNilNode(t *testing.T) {
	for _, who := range []*apitype.WhoIsResponse{nil, {Node: nil}} {
		nodeID, provenance, ok := peerNodeIDFromWhoIs(who)
		if ok || nodeID != "" || provenance != "" {
			t.Fatalf("nil node wrongly accepted: nodeID=%q provenance=%q ok=%t", nodeID, provenance, ok)
		}
	}
}
