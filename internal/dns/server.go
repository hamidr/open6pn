package dns

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"open6pn/internal/addr"
)

// maxAnswers bounds a response. Names with more endpoints are answered with a
// random subset, which also spreads load.
const maxAnswers = 24

// Limits on what containers can make the resolver do. Every container on the
// host shares it, so one network must not be able to use it up.
const (
	// DefaultForwards is how many queries may be waiting for an upstream
	// resolver at once, and DefaultNetworkForwards how many of those may
	// belong to one network. Each holds a socket for up to a few seconds.
	DefaultForwards        = 512
	DefaultNetworkForwards = 32
	// DefaultTCPConns and DefaultNetworkTCPConns bound open TCP connections
	// the same way.
	DefaultTCPConns        = 256
	DefaultNetworkTCPConns = 8
)

// Server answers <name>.<domain> from the zone and forwards everything else.
//
// The network a query belongs to is read from its source address. That is
// safe because the resolver's address only exists for packets that came in
// through a container's veth and passed the datapath's source check there,
// and the answer is routed back to that same address.
type Server struct {
	Zone      *Zone
	Layout    addr.Layout
	NodeID    uint16
	Domain    string   // e.g. "internal"
	Upstreams []string // host:port; empty means other names are refused
	TTL       uint32

	// Zero means the default.
	Forwards, NetworkForwards int
	TCPConns, NetworkTCPConns int

	fqdnOnce sync.Once
	fqdn     string
	udp, tcp *mdns.Server
	forwards limiter
}

// limiter counts things in use, in total and per network.
type limiter struct {
	mu     sync.Mutex
	total  int
	perNet map[uint32]int
}

func (l *limiter) acquire(network uint32, maxTotal, maxNet int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxTotal || l.perNet[network] >= maxNet {
		return false
	}
	if l.perNet == nil {
		l.perNet = make(map[uint32]int)
	}
	l.total++
	l.perNet[network]++
	return true
}

func (l *limiter) release(network uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perNet[network]--; l.perNet[network] <= 0 {
		delete(l.perNet, network)
	}
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// limitListener closes connections beyond the limits as soon as they are
// accepted.
type limitListener struct {
	net.Listener
	s     *Server
	conns limiter
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		network, ok := l.s.networkOf(c.RemoteAddr())
		if !ok || !l.conns.acquire(network, orDefault(l.s.TCPConns, DefaultTCPConns), orDefault(l.s.NetworkTCPConns, DefaultNetworkTCPConns)) {
			c.Close()
			continue
		}
		return &limitConn{Conn: c, release: func() { l.conns.release(network) }}, nil
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// Start listens on addrPort for UDP and TCP.
func (s *Server) Start(addrPort string) error {
	lc := net.ListenConfig{Control: freebind}
	pc, err := lc.ListenPacket(context.Background(), "udp6", addrPort)
	if err != nil {
		return err
	}
	ln, err := lc.Listen(context.Background(), "tcp6", addrPort)
	if err != nil {
		pc.Close()
		return err
	}
	ln = &limitListener{Listener: ln, s: s}
	s.udp = &mdns.Server{PacketConn: pc, Handler: s}
	s.tcp = &mdns.Server{Listener: ln, Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: func() time.Duration { return 5 * time.Second }}
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	return nil
}

// Stop shuts the listeners down.
func (s *Server) Stop() {
	if s.udp != nil {
		s.udp.Shutdown()
	}
	if s.tcp != nil {
		s.tcp.Shutdown()
	}
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	s.fqdnOnce.Do(func() { s.fqdn = mdns.Fqdn(strings.ToLower(s.Domain)) })
	network, ok := s.networkOf(w.RemoteAddr())
	if !ok || len(r.Question) != 1 {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeRefused)
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	_, isUDP := w.RemoteAddr().(*net.UDPAddr)

	if !mdns.IsSubDomain(s.fqdn, name) {
		// Forwarding waits on someone else. Past the limits, say so at
		// once rather than queue: the client retries.
		if !s.forwards.acquire(network, orDefault(s.Forwards, DefaultForwards), orDefault(s.NetworkForwards, DefaultNetworkForwards)) {
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		defer s.forwards.release(network)
		s.forward(w, r, isUDP)
		return
	}

	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true

	label := strings.TrimSuffix(strings.TrimSuffix(name, s.fqdn), ".")
	recs, found := []Record(nil), label == ""
	if label != "" {
		recs, found = s.Zone.Lookup(network, label)
	}
	if !found {
		m.Rcode = mdns.RcodeNameError
	}
	if q.Qclass == mdns.ClassINET {
		rand.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })
		if len(recs) > maxAnswers {
			recs = recs[:maxAnswers]
		}
		for _, rec := range recs {
			hdr := mdns.RR_Header{Name: q.Name, Class: mdns.ClassINET, Ttl: s.TTL}
			if q.Qtype == mdns.TypeAAAA || q.Qtype == mdns.TypeANY {
				hdr.Rrtype = mdns.TypeAAAA
				m.Answer = append(m.Answer, &mdns.AAAA{Hdr: hdr, AAAA: addr.V6(rec.Node, network, rec.Ep).AsSlice()})
			}
			if q.Qtype == mdns.TypeA || q.Qtype == mdns.TypeANY {
				hdr.Rrtype = mdns.TypeA
				m.Answer = append(m.Answer, &mdns.A{Hdr: hdr, A: s.Layout.V4(rec.Node, rec.Ep).AsSlice()})
			}
		}
	}
	if len(m.Answer) == 0 {
		// Lets resolvers cache the negative answer for a moment.
		m.Ns = []mdns.RR{&mdns.SOA{
			Hdr:     mdns.RR_Header{Name: s.fqdn, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: s.TTL},
			Ns:      "ns." + s.fqdn,
			Mbox:    "hostmaster." + s.fqdn,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  s.TTL,
		}}
	}
	if isUDP {
		size := mdns.MinMsgSize
		if opt := r.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		m.Truncate(size)
	}
	w.WriteMsg(m)
}

// networkOf returns the network a query came from. Queries from anywhere but
// a container endpoint on this host are refused.
func (s *Server) networkOf(remote net.Addr) (uint32, bool) {
	var ip netip.Addr
	switch a := remote.(type) {
	case *net.UDPAddr:
		ip = a.AddrPort().Addr()
	case *net.TCPAddr:
		ip = a.AddrPort().Addr()
	default:
		return 0, false
	}
	node, network, ep, err := addr.Parse6(ip)
	if err != nil || node != s.NodeID || network == 0 || !s.Layout.ValidEndpoint(ep) {
		return 0, false
	}
	return network, true
}

func (s *Server) forward(w mdns.ResponseWriter, r *mdns.Msg, udp bool) {
	c := &mdns.Client{Net: "tcp", Timeout: 3 * time.Second}
	if udp {
		c.Net = "udp"
		if opt := r.IsEdns0(); opt != nil {
			c.UDPSize = opt.UDPSize()
		}
	}
	for _, up := range s.Upstreams {
		resp, _, err := c.Exchange(r, up)
		if err != nil {
			continue
		}
		w.WriteMsg(resp)
		return
	}
	m := new(mdns.Msg)
	if len(s.Upstreams) == 0 {
		m.SetRcode(r, mdns.RcodeRefused)
	} else {
		m.SetRcode(r, mdns.RcodeServerFailure)
	}
	w.WriteMsg(m)
}

// SystemUpstreams reads the host's resolvers from resolv.conf.
func SystemUpstreams(path string) ([]string, error) {
	cfg, err := mdns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, srv := range cfg.Servers {
		ip, err := netip.ParseAddr(srv)
		if err != nil || ip == addr.DNS {
			continue
		}
		out = append(out, net.JoinHostPort(srv, cfg.Port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no usable nameserver", path)
	}
	return out, nil
}
