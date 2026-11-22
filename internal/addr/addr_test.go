package addr

import (
	"net/netip"
	"testing"
)

func TestLayout(t *testing.T) {
	// The worked example from the design: node 0x02a, network 0xbeef, endpoint 7.
	if got, want := V6(0x02a, 0xbeef, 7), netip.MustParseAddr("fdaa:2a:0:beef::7"); got != want {
		t.Errorf("V6 = %s, want %s", got, want)
	}
	if got, want := NodePrefix(0x02a), netip.MustParsePrefix("fdaa:2a::/32"); got != want {
		t.Errorf("NodePrefix = %s, want %s", got, want)
	}
	for _, c := range []struct {
		bits int
		want string
	}{{12, "10.2.160.7"}, {14, "10.0.168.7"}, {16, "10.0.42.7"}} {
		if got := (Layout{c.bits}).V4(0x02a, 7); got != netip.MustParseAddr(c.want) {
			t.Errorf("V4 with %d node bits = %s, want %s", c.bits, got, c.want)
		}
	}
}

func TestBounds(t *testing.T) {
	for _, c := range []struct {
		bits            int
		maxNode, maxEp  uint16
		first, lastAddr string
	}{
		{8, 255, 65534, "10.1.0.1", "10.255.255.254"},
		{12, 4095, 4094, "10.0.16.1", "10.255.255.254"},
		{14, 16383, 1022, "10.0.4.1", "10.255.255.254"},
		{16, 65535, 254, "10.0.1.1", "10.255.255.254"},
	} {
		l := Layout{c.bits}
		if err := l.Validate(); err != nil {
			t.Errorf("%d node bits: %v", c.bits, err)
		}
		if l.MaxNode() != c.maxNode || l.MaxEndpoint() != c.maxEp {
			t.Errorf("%d node bits: max node %d, max endpoint %d; want %d, %d", c.bits, l.MaxNode(), l.MaxEndpoint(), c.maxNode, c.maxEp)
		}
		if got := l.V4(1, 1); got != netip.MustParseAddr(c.first) {
			t.Errorf("%d node bits: first address %s, want %s", c.bits, got, c.first)
		}
		if got := l.V4(l.MaxNode(), l.MaxEndpoint()); got != netip.MustParseAddr(c.lastAddr) {
			t.Errorf("%d node bits: last address %s, want %s", c.bits, got, c.lastAddr)
		}
		if l.ValidNode(0) || !l.ValidNode(c.maxNode) || l.ValidEndpoint(0) || !l.ValidEndpoint(c.maxEp) || l.ValidEndpoint(c.maxEp+1) {
			t.Errorf("%d node bits: ID validity bounds are wrong", c.bits)
		}
		if c.bits < 16 && l.ValidNode(c.maxNode+1) {
			t.Errorf("%d node bits: node %d must not be valid", c.bits, c.maxNode+1)
		}
		if !Cluster6.Contains(V6(l.MaxNode(), 1<<32-1, l.MaxEndpoint())) {
			t.Errorf("%d node bits: maximum IPv6 address falls outside %s", c.bits, Cluster6)
		}
	}
	for _, bits := range []int{0, 7, 17, 24} {
		if (Layout{bits}).Validate() == nil {
			t.Errorf("%d node bits must be refused", bits)
		}
	}
}

// Within a layout, no two (node, endpoint) pairs may share an IPv4 address.
func TestV4Unique(t *testing.T) {
	for bits := MinNodeBits; bits <= MaxNodeBits; bits++ {
		l := Layout{bits}
		seen := make(map[netip.Addr]bool)
		nodes := []uint16{1, 2, l.MaxNode() - 1, l.MaxNode()}
		eps := []uint16{1, 2, l.MaxEndpoint() - 1, l.MaxEndpoint()}
		for _, n := range nodes {
			for _, e := range eps {
				a := l.V4(n, e)
				if seen[a] || !Cluster4.Contains(a) {
					t.Errorf("%d node bits: node %d endpoint %d gives %s, a duplicate or outside %s", bits, n, e, a, Cluster4)
				}
				seen[a] = true
			}
		}
	}
}

func TestParse6RoundTrip(t *testing.T) {
	for _, c := range []struct {
		node uint16
		net  uint32
		ep   uint16
	}{{1, 1, 1}, {4095, 1<<32 - 1, 4094}, {65535, 1, 254}, {7, 0xdeadbeef, 300}} {
		node, net, ep, err := Parse6(V6(c.node, c.net, c.ep))
		if err != nil || node != c.node || net != c.net || ep != c.ep {
			t.Errorf("Parse6(V6(%v)) = %d %d %d %v", c, node, net, ep, err)
		}
	}
	for _, bad := range []string{"fe80::1", "fdab::1", "10.0.0.1", "fdaa:1:0:1:1::1", "::ffff:10.0.0.1"} {
		if _, _, _, err := Parse6(netip.MustParseAddr(bad)); err == nil {
			t.Errorf("Parse6(%s) succeeded, want error", bad)
		}
	}
}

// Two networks must never share an IPv6 address, whatever the node/endpoint.
func TestNetworksDisjoint(t *testing.T) {
	a := netip.PrefixFrom(V6(5, 100, 0), 64)
	b := netip.PrefixFrom(V6(5, 101, 0), 64)
	if a.Overlaps(b) {
		t.Errorf("%s overlaps %s", a, b)
	}
}
