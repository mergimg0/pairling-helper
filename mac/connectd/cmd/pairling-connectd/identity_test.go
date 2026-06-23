package main

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestNodeIdentityFromStatusReadsGrantedSelf(t *testing.T) {
	grantedTags := views.SliceOf([]string{"tag:pairling-connect"})
	requestedTags := []string{"tag:requested-only"}

	identity := nodeIdentityFromStatus(&ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			ID:           tailcfg.StableNodeID("nXb6CNTRL"),
			Tags:         &grantedTags,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.79.217.7")},
		},
	})

	if identity.NodeID != "nXb6CNTRL" {
		t.Fatalf("node ID = %q, want nXb6CNTRL", identity.NodeID)
	}
	if !reflect.DeepEqual(identity.Tags, []string{"tag:pairling-connect"}) {
		t.Fatalf("tags = %#v, want granted tags only", identity.Tags)
	}
	if reflect.DeepEqual(identity.Tags, requestedTags) {
		t.Fatalf("mapper reported requested tags instead of granted tags: %#v", identity.Tags)
	}
	if !reflect.DeepEqual(identity.TailnetIPs, []string{"100.79.217.7"}) {
		t.Fatalf("tailnet IPs = %#v", identity.TailnetIPs)
	}
}

func TestNodeIdentityFromStatusHandlesNilSelf(t *testing.T) {
	for _, st := range []*ipnstate.Status{nil, {}} {
		identity := nodeIdentityFromStatus(st)
		if identity.NodeID != "" || len(identity.Tags) != 0 || len(identity.TailnetIPs) != 0 {
			t.Fatalf("nil self identity = %#v, want zero value", identity)
		}
	}
}

func TestNodeIdentityFromStatusUntaggedNode(t *testing.T) {
	identity := nodeIdentityFromStatus(&ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			ID:           tailcfg.StableNodeID("nInteractive"),
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.79.217.8")},
		},
	})

	if identity.NodeID != "nInteractive" {
		t.Fatalf("node ID = %q, want nInteractive", identity.NodeID)
	}
	if len(identity.Tags) != 0 {
		t.Fatalf("untagged node reported tags: %#v", identity.Tags)
	}
	if !reflect.DeepEqual(identity.TailnetIPs, []string{"100.79.217.8"}) {
		t.Fatalf("tailnet IPs = %#v", identity.TailnetIPs)
	}
}
