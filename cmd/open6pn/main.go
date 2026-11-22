//go:build linux

// Command open6pn is the private-network daemon and its CLI.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"open6pn/internal/agent"
	"open6pn/internal/api"
	"open6pn/internal/dns"
	"open6pn/internal/store"
)

const usage = `open6pn - private networks for containers across hosts

Daemon (one per host; starting it joins the host to the mesh):
  open6pn daemon --etcd URL[,URL...] [--advertise IP] [flags]

Networks:
  open6pn network create NAME
  open6pn network ls
  open6pn network rm [--force] NAME|ID
  open6pn network endpoints NAME|ID      endpoints on every host

Endpoints (on this host):
  open6pn attach --netns PATH [--ifname o6pn0] [--name NAME]... NETWORK
  open6pn attach --veth HOSTIF --netns PATH [--name NAME]... NETWORK
  open6pn attach --veth HOSTIF --mac CONTAINER-MAC [--name NAME]... NETWORK
  open6pn detach ENDPOINT-ID|HOSTIF
  open6pn endpoint ls

Hosts:
  open6pn status
  open6pn node ls
  open6pn node rm ID

Run a command with -h for its flags. OPEN6PN_SOCKET overrides the daemon socket.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "daemon":
		err = runDaemon(args)
	case "status":
		err = runStatus(args)
	case "node", "nodes":
		err = runNode(args)
	case "network", "networks", "net":
		err = runNetwork(args)
	case "attach":
		err = runAttach(args)
	case "detach":
		err = runDetach(args)
	case "endpoint", "endpoints", "ep":
		err = runEndpoint(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "open6pn: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "open6pn:", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("open6pn "+name, flag.ExitOnError)
	socket := fs.String("socket", envOr("OPEN6PN_SOCKET", api.DefaultSocket), "daemon socket")
	return fs, socket
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// ---- daemon ----

func runDaemon(args []string) error {
	fs, socket := newFlags("daemon")
	var (
		etcd       = fs.String("etcd", os.Getenv("OPEN6PN_ETCD"), "etcd endpoints, comma-separated (required)")
		etcdPrefix = fs.String("etcd-prefix", "/open6pn", "key prefix; one prefix is one mesh")
		etcdCA     = fs.String("etcd-ca", "", "CA certificate for etcd")
		etcdCert   = fs.String("etcd-cert", "", "client certificate for etcd")
		etcdKey    = fs.String("etcd-key", "", "client key for etcd")
		etcdUser   = fs.String("etcd-user", os.Getenv("OPEN6PN_ETCD_USER"), "etcd user")
		advertise  = fs.String("advertise", "", "IP other hosts reach this host on (default: the default route's source address)")
		wgPort     = fs.Int("wg-port", 51820, "WireGuard UDP port")
		mtu        = fs.Int("mtu", 0, "first host only: WireGuard MTU; containers get 40 less (default 1420). The same on every host of a cluster")
		name       = fs.String("name", "", "node name (default: hostname)")
		stateDir   = fs.String("state-dir", "/var/lib/open6pn", "where the node identity and endpoint state are kept")
		domain     = fs.String("dns-domain", "internal", "domain endpoint names are served under")
		upstream   = fs.String("dns-upstream", "", "resolvers for other names, comma-separated (default: from /etc/resolv.conf)")
		ttl        = fs.Duration("endpoint-ttl", time.Minute, "how long this host's DNS records outlive its daemon")
		peerThr    = fs.Bool("wg-peer-threads", false, "keep the kernel thread WireGuard starts per peer on Linux 6.16+ (about 24 KB and one thread for every other host)")
		maxHosts   = fs.Int("max-network-hosts", 1<<20, "size of the table of (network, host) pairs containers may send to: for each network this host serves, one entry per other host serving it. About 16 bytes of kernel memory each, reserved up front. Changing it rebuilds the datapath's tables")
		nodeBits   = fs.Int("node-bits", 0, "first host only: bits of the IPv4 address that number the host, 8-16 (default 14: 16383 hosts, 1022 endpoints per network per host; 16: 65535 hosts, 254). Fixed once the cluster exists")
		debug      = fs.Bool("debug", false, "verbose logging")
	)
	fs.Parse(args)

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *etcd == "" {
		return errors.New("--etcd is required")
	}
	if *mtu != 0 && (*mtu < 1280+40 || *mtu > 65535) {
		return errors.New("--mtu must be at least 1320, so that containers keep the IPv6 minimum of 1280, and at most 65535")
	}
	if *maxHosts < 1024 || *maxHosts > 1<<26 {
		return errors.New("--max-network-hosts must be between 1024 and 67108864")
	}
	if *ttl < 10*time.Second {
		return errors.New("--endpoint-ttl must be at least 10s")
	}
	cfg := agent.Config{
		StateDir:        *stateDir,
		Socket:          *socket,
		NodeName:        *name,
		WGPort:          *wgPort,
		MTU:             *mtu,
		DNSDomain:       strings.ToLower(strings.Trim(*domain, ".")),
		EndpointTTL:     *ttl,
		NodeBits:        *nodeBits,
		WGPeerThreads:   *peerThr,
		MaxNetworkHosts: *maxHosts,
		Store: store.Config{
			Endpoints: strings.Split(*etcd, ","),
			Prefix:    *etcdPrefix,
			Username:  *etcdUser,
			Password:  os.Getenv("OPEN6PN_ETCD_PASSWORD"),
		},
	}
	if cfg.NodeName == "" {
		cfg.NodeName, _ = os.Hostname()
	}

	var err error
	if *etcdCA != "" || *etcdCert != "" {
		if cfg.Store.TLS, err = etcdTLS(*etcdCA, *etcdCert, *etcdKey); err != nil {
			return err
		}
	}
	if *advertise != "" {
		if cfg.Advertise, err = netip.ParseAddr(*advertise); err != nil {
			return fmt.Errorf("--advertise: %w", err)
		}
	} else {
		if cfg.Advertise, err = defaultSourceAddr(); err != nil {
			return fmt.Errorf("cannot work out this host's address; pass --advertise: %w", err)
		}
		log.Info("advertising the default route's source address; pass --advertise if other hosts cannot reach it", "addr", cfg.Advertise)
	}
	if *upstream != "" {
		for _, u := range strings.Split(*upstream, ",") {
			if _, _, err := net.SplitHostPort(u); err != nil {
				u = net.JoinHostPort(u, "53")
			}
			cfg.DNSUpstreams = append(cfg.DNSUpstreams, u)
		}
	} else if cfg.DNSUpstreams, err = dns.SystemUpstreams("/etc/resolv.conf"); err != nil {
		log.Warn("no upstream resolvers; containers will only resolve mesh names", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, cfg, log)
}

func etcdTLS(ca, cert, key string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificates", ca)
		}
	}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// defaultSourceAddr asks the kernel which address it would use to reach the
// internet. Connecting a UDP socket sends nothing.
func defaultSourceAddr() (netip.Addr, error) {
	var lastErr error
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		c, err := net.Dial("udp", target)
		if err != nil {
			lastErr = err
			continue
		}
		ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
		c.Close()
		return ap.Addr().Unmap(), nil
	}
	return netip.Addr{}, lastErr
}

// ---- client commands ----

func table(header string, rows func(w *tabwriter.Writer)) {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, header)
	rows(w)
	w.Flush()
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runStatus(args []string) error {
	fs, socket := newFlags("status")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)
	st, err := api.NewClient(*socket).Status()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(st)
	}
	fmt.Printf("node        %d (%s)\n", st.Node.ID, st.Node.Name)
	fmt.Printf("endpoint    %s\n", st.Node.Endpoint)
	fmt.Printf("public key  %s\n", st.Node.PublicKey)
	fmt.Printf("peers       %d\n", st.Peers)
	fmt.Printf("limits      %d hosts, %d endpoints per network per host (%d node bits)\n", st.Layout.MaxNodes, st.Layout.MaxEndpoints, st.Layout.NodeBits)
	fmt.Printf("endpoints   %d in %d network(s)\n", st.Endpoints, st.Networks)
	fmt.Println("datapath")
	names := make([]string, 0, len(st.Stats))
	for k := range st.Stats {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Printf("  %-18s %d\n", k, st.Stats[k])
	}
	return nil
}

func runNode(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: open6pn node ls | rm ID")
	}
	fs, socket := newFlags("node " + args[0])
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args[1:])
	c := api.NewClient(*socket)
	switch args[0] {
	case "ls", "list":
		nodes, err := c.Nodes()
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(nodes)
		}
		table("ID\tNAME\tENDPOINT\tPUBLIC KEY", func(w *tabwriter.Writer) {
			for _, n := range nodes {
				name := n.Name
				if n.Self {
					name += " (this host)"
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", n.ID, name, n.Endpoint, n.PublicKey)
			}
		})
		return nil
	case "rm", "remove":
		if fs.NArg() != 1 {
			return errors.New("usage: open6pn node rm ID")
		}
		id, err := strconv.ParseUint(fs.Arg(0), 10, 16)
		if err != nil {
			return fmt.Errorf("invalid node ID %q", fs.Arg(0))
		}
		return c.RemoveNode(uint16(id))
	}
	return fmt.Errorf("unknown node command %q", args[0])
}

func runNetwork(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: open6pn network create NAME | ls | rm NAME|ID | endpoints NAME|ID")
	}
	fs, socket := newFlags("network " + args[0])
	asJSON := fs.Bool("json", false, "print JSON")
	force := fs.Bool("force", false, "rm: remove even if endpoints are attached")
	fs.Parse(args[1:])
	c := api.NewClient(*socket)
	switch args[0] {
	case "create", "add":
		if fs.NArg() != 1 {
			return errors.New("usage: open6pn network create NAME")
		}
		n, err := c.CreateNetwork(fs.Arg(0))
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(n)
		}
		fmt.Printf("%s (id %d)\n", n.Name, n.ID)
		return nil
	case "ls", "list":
		nets, err := c.Networks()
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(nets)
		}
		table("ID\tNAME\tCREATED", func(w *tabwriter.Writer) {
			for _, n := range nets {
				fmt.Fprintf(w, "%d\t%s\t%s\n", n.ID, n.Name, n.CreatedAt.Format(time.RFC3339))
			}
		})
		return nil
	case "rm", "remove":
		if fs.NArg() != 1 {
			return errors.New("usage: open6pn network rm [--force] NAME|ID")
		}
		return c.RemoveNetwork(fs.Arg(0), *force)
	case "endpoints", "eps":
		if fs.NArg() != 1 {
			return errors.New("usage: open6pn network endpoints NAME|ID")
		}
		eps, err := c.NetworkEndpoints(fs.Arg(0))
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(eps)
		}
		table("NODE\tIPV6\tIPV4\tNAMES", func(w *tabwriter.Writer) {
			for _, e := range eps {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", e.NodeID, e.IPv6, e.IPv4, strings.Join(e.Names, ","))
			}
		})
		return nil
	}
	return fmt.Errorf("unknown network command %q", args[0])
}

func runAttach(args []string) error {
	fs, socket := newFlags("attach")
	var names stringList
	fs.Var(&names, "name", "DNS name for the endpoint, served as NAME.<dns-domain>; repeatable")
	netns := fs.String("netns", "", "the container's network namespace, e.g. /proc/PID/ns/net")
	veth := fs.String("veth", "", "host side of an existing veth pair (default: create one)")
	ifname := fs.String("ifname", "o6pn0", "name of a created interface inside the container")
	mac := fs.String("mac", "", "MAC address of the container side, when --netns is not given")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: open6pn attach [flags] NETWORK (flags come first)")
	}
	ep, err := api.NewClient(*socket).Attach(api.AttachRequest{
		Network:      fs.Arg(0),
		Names:        names,
		Netns:        *netns,
		HostIf:       *veth,
		ContainerIf:  *ifname,
		ContainerMAC: *mac,
	})
	if err != nil {
		return err
	}
	return printJSON(ep)
}

func runDetach(args []string) error {
	fs, socket := newFlags("detach")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: open6pn detach ENDPOINT-ID|HOSTIF")
	}
	return api.NewClient(*socket).Detach(fs.Arg(0))
}

func runEndpoint(args []string) error {
	if len(args) == 0 || (args[0] != "ls" && args[0] != "list") {
		return errors.New("usage: open6pn endpoint ls")
	}
	fs, socket := newFlags("endpoint ls")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args[1:])
	eps, err := api.NewClient(*socket).Endpoints()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(eps)
	}
	table("ID\tNETWORK\tIPV6\tIPV4\tINTERFACE\tNAMES", func(w *tabwriter.Writer) {
		for _, e := range eps {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Network, e.IPv6, e.IPv4, e.HostIf, strings.Join(e.Names, ","))
		}
	})
	return nil
}
