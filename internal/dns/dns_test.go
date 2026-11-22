package dns

import (
	"net"
	"net/netip"
	"sort"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"open6pn/internal/addr"
)

type fakeWriter struct {
	remote net.Addr
	msg    *mdns.Msg
}

func (f *fakeWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (f *fakeWriter) RemoteAddr() net.Addr        { return f.remote }
func (f *fakeWriter) WriteMsg(m *mdns.Msg) error  { f.msg = m; return nil }
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)         {}
func (f *fakeWriter) Hijack()                     {}

func query(s *Server, from netip.Addr, name string, qtype uint16) *mdns.Msg {
	w := &fakeWriter{remote: net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 40000))}
	r := new(mdns.Msg)
	r.SetQuestion(name, qtype)
	s.ServeDNS(w, r)
	return w.msg
}

func answers(m *mdns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *mdns.AAAA:
			out = append(out, v.AAAA.String())
		case *mdns.A:
			out = append(out, v.A.String())
		}
	}
	sort.Strings(out)
	return out
}

func newServer() *Server {
	z := NewZone()
	// Network 1: "web" on two hosts, "db" on one.
	z.Set(1, Record{Node: 5, Ep: 1}, []string{"web"})
	z.Set(1, Record{Node: 9, Ep: 3}, []string{"web", "web.ams"})
	z.Set(1, Record{Node: 9, Ep: 4}, []string{"db"})
	// Network 2 reuses the names and, deliberately, the same node/endpoint IDs.
	z.Set(2, Record{Node: 5, Ep: 1}, []string{"web", "secret"})
	return &Server{Zone: z, Layout: addr.Layout{NodeBits: 12}, NodeID: 5, Domain: "internal", TTL: 5}
}

func TestAnswersWithinNetwork(t *testing.T) {
	s := newServer()
	from := addr.V6(5, 1, 1)

	m := query(s, from, "web.internal.", mdns.TypeAAAA)
	if got := answers(m); len(got) != 2 || got[0] != "fdaa:5:0:1::1" || got[1] != "fdaa:9:0:1::3" {
		t.Errorf("AAAA web = %v", got)
	}
	m = query(s, from, "WEB.Internal.", mdns.TypeA)
	if got := answers(m); len(got) != 2 || got[0] != "10.0.144.3" || got[1] != "10.0.80.1" {
		t.Errorf("A web = %v", got)
	}
	m = query(s, from, "web.ams.internal.", mdns.TypeAAAA)
	if got := answers(m); len(got) != 1 || got[0] != "fdaa:9:0:1::3" {
		t.Errorf("AAAA web.ams = %v", got)
	}
	// A name that exists, asked for a type it does not have: empty, not NXDOMAIN.
	m = query(s, from, "db.internal.", mdns.TypeMX)
	if m.Rcode != mdns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Errorf("MX db: rcode=%d answers=%d ns=%d", m.Rcode, len(m.Answer), len(m.Ns))
	}
}

func TestNetworksCannotSeeEachOther(t *testing.T) {
	s := newServer()

	// "secret" exists only in network 2.
	if m := query(s, addr.V6(5, 1, 1), "secret.internal.", mdns.TypeAAAA); m.Rcode != mdns.RcodeNameError || len(m.Answer) != 0 {
		t.Errorf("network 1 resolved network 2's name: rcode=%d answers=%v", m.Rcode, answers(m))
	}
	// "web" exists in both; each side must only get its own.
	if got := answers(query(s, addr.V6(5, 2, 1), "web.internal.", mdns.TypeAAAA)); len(got) != 1 || got[0] != "fdaa:5:0:2::1" {
		t.Errorf("network 2 web = %v", got)
	}
	// "db" exists only in network 1.
	if m := query(s, addr.V6(5, 2, 1), "db.internal.", mdns.TypeA); m.Rcode != mdns.RcodeNameError {
		t.Errorf("network 2 resolved network 1's name: rcode=%d", m.Rcode)
	}
}

func TestRefusesNonEndpointSources(t *testing.T) {
	s := newServer()
	for _, from := range []string{
		"fdaa:9:0:1::3", // an endpoint, but on another host
		"fdaa:5::1",     // network 0
		"fe80::1",
		"2001:db8::1",
		"fdaa::53",
	} {
		if m := query(s, netip.MustParseAddr(from), "web.internal.", mdns.TypeAAAA); m.Rcode != mdns.RcodeRefused || len(m.Answer) != 0 {
			t.Errorf("query from %s: rcode=%d answers=%v", from, m.Rcode, answers(m))
		}
	}
}

func TestOtherDomainsRefusedWithoutUpstream(t *testing.T) {
	s := newServer()
	if m := query(s, addr.V6(5, 1, 1), "example.com.", mdns.TypeA); m.Rcode != mdns.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED", m.Rcode)
	}
}

func TestZoneUpdates(t *testing.T) {
	z := NewZone()
	z.Set(1, Record{5, 1}, []string{"a", "b"})
	z.Set(1, Record{5, 1}, []string{"b", "c"}) // rename
	if _, ok := z.Lookup(1, "a"); ok {
		t.Error("old name survived a rename")
	}
	if r, _ := z.Lookup(1, "c"); len(r) != 1 {
		t.Errorf("c = %v", r)
	}

	// A resync from etcd replaces other hosts' records and keeps ours.
	z.Set(1, Record{7, 2}, []string{"b"})
	z.ReplaceRemote(1, 5, map[Record][]string{{8, 9}: {"b"}})
	r, _ := z.Lookup(1, "b")
	sort.Slice(r, func(i, j int) bool { return r[i].Node < r[j].Node })
	if len(r) != 2 || r[0] != (Record{5, 1}) || r[1] != (Record{8, 9}) {
		t.Errorf("after resync b = %v", r)
	}

	z.Delete(1, Record{5, 1})
	z.Delete(1, Record{8, 9})
	if _, ok := z.Lookup(1, "b"); ok {
		t.Error("name survived its last endpoint")
	}
	z.Drop(1)
	if _, ok := z.Lookup(1, "c"); ok {
		t.Error("dropped network still resolves")
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{"Web": "web", "web.ams.": "web.ams", "a-1": "a-1"} {
		if got, err := NormalizeName(in); err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-a", "a..b", "a_b", "a b", "*.a"} {
		if _, err := NormalizeName(bad); err == nil {
			t.Errorf("NormalizeName(%q) succeeded", bad)
		}
	}
}

// One network must not be able to use up the resolver's forwarding: beyond
// its share it is refused at once, and other networks are still served.
func TestForwardLimits(t *testing.T) {
	// An upstream resolver that holds every query until it is released.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	release := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(mdns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			go func() {
				<-release
				r := new(mdns.Msg)
				r.SetReply(q)
				b, _ := r.Pack()
				pc.WriteTo(b, from)
			}()
		}
	}()

	s := newServer()
	s.Upstreams = []string{pc.LocalAddr().String()}
	s.NetworkForwards = 2
	s.Forwards = 3
	net1, net2, net3 := addr.V6(5, 1, 1), addr.V6(5, 2, 1), addr.V6(5, 3, 1)

	results := make(chan int, 3)
	ask := func(from netip.Addr) { results <- query(s, from, "example.com.", mdns.TypeA).Rcode }
	inFlight := func() int {
		s.forwards.mu.Lock()
		defer s.forwards.mu.Unlock()
		return s.forwards.total
	}
	waitFor := func(n int) {
		t.Helper()
		for range 200 {
			if inFlight() == n {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("%d queries in flight, want %d", inFlight(), n)
	}

	go ask(net1)
	go ask(net1)
	waitFor(2)
	if rc := query(s, net1, "example.com.", mdns.TypeA).Rcode; rc != mdns.RcodeServerFailure {
		t.Errorf("third query of a network at its limit: rcode %d, want SERVFAIL", rc)
	}
	if got := answers(query(s, net1, "web.internal.", mdns.TypeAAAA)); len(got) != 2 {
		t.Errorf("local names must still resolve for a network at its limit, got %v", got)
	}
	go ask(net2)
	waitFor(3)
	if rc := query(s, net3, "example.com.", mdns.TypeA).Rcode; rc != mdns.RcodeServerFailure {
		t.Errorf("query beyond the total limit: rcode %d, want SERVFAIL", rc)
	}

	close(release)
	for range 3 {
		if rc := <-results; rc != mdns.RcodeSuccess {
			t.Errorf("held query finished with rcode %d, want success", rc)
		}
	}
	waitFor(0)
}
