//go:build linux

// Package agent is the open6pn daemon: one per host.
//
// It is level-triggered throughout. Local endpoints live in the state file
// and are pushed into the kernel and into etcd; the node list and the other
// hosts' endpoints live in etcd and are pulled into WireGuard and the
// resolver. Either direction can be replayed from scratch at any time, which
// is what happens on restart and after any loss of contact with etcd.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"open6pn/internal/addr"
	"open6pn/internal/api"
	"open6pn/internal/datapath"
	"open6pn/internal/dns"
	"open6pn/internal/state"
	"open6pn/internal/store"
)

// Config is the daemon's configuration.
type Config struct {
	StateDir  string
	Socket    string
	NodeName  string
	Advertise netip.Addr // address other hosts reach this one's WireGuard port on
	WGPort    int
	// MTU of the WireGuard device, for the first host of a cluster. Zero
	// means the default, or whatever the cluster has.
	MTU          int
	DNSDomain    string
	DNSUpstreams []string
	EndpointTTL  time.Duration
	// NodeBits creates the cluster with this address layout if this is its
	// first host. Zero means the default, or whatever the cluster has.
	NodeBits int
	// WGPeerThreads keeps the kernel's one-thread-per-peer receive mode.
	WGPeerThreads bool
	// MaxNetworkHosts sizes the table of (network, host) pairs containers
	// may send to. Zero means the default.
	MaxNetworkHosts int
	Store           store.Config
}

type pubKey struct {
	net uint32
	ep  uint16
}

type netWatch struct {
	refs   int
	cancel context.CancelFunc
	// identity is the network this host means by the ID. Records other
	// hosts publish under the ID for a different network are not ours.
	identity store.NetworkIdentity
	foreign  bool // such a record has been seen and reported
	// ready is closed once the network's endpoints on other hosts have
	// been read for the first time.
	ready     chan struct{}
	readyOnce sync.Once
}

// peerGrace is how long containers may keep sending to a host after its last
// endpoint in their network has disappeared from etcd. A host that loses
// contact with etcd loses its records there while its containers carry on;
// traffic to them must not stop on that account.
const peerGrace = time.Hour

// maxCursors bounds the endpoint ID cursors kept for networks this host no
// longer serves.
const maxCursors = 4096

// Agent is a running daemon.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	layout addr.Layout
	mtu    int // of the WireGuard device; the same on every host
	store  *store.Store
	dir    *state.Dir
	dp     *datapath.Datapath
	zone   *dns.Zone
	node   store.Node
	key    wgtypes.Key
	ctx    context.Context

	// fail stops the daemon with an error. gone is set when it stops
	// because this host no longer owns its node ID.
	fail context.CancelCauseFunc
	gone atomic.Bool

	repairTick int // which housekeeping tick checks the network ID counter

	mu        sync.Mutex
	meta      *state.State               // state.json
	metaDirty bool                       // meta has changes worth writing, but not urgently
	endpoints map[string]*state.Endpoint // by ID
	cursor    map[uint32]uint16          // next endpoint ID to try, per network
	watchers  map[uint32]*netWatch
	withdrawn map[pubKey]struct{} // detached, still to be deleted from etcd
	dirty     chan struct{}
	// netPeers is, for every network this host serves, the endpoints other
	// hosts have in it: network -> node -> endpoint IDs. Containers may
	// send to exactly those nodes, and for peerGrace to those in grace.
	netPeers   map[uint32]map[uint16]map[uint16]struct{}
	grace      map[datapath.NetNode]time.Time
	fullLogged time.Time // when that table was last reported full

	peersMu    sync.Mutex
	peers      map[uint16]store.Node
	peersKnown bool          // the node list has been read at least once
	peersRetry chan struct{} // a WireGuard update failed; reconcile soon
}

// Run starts the daemon and blocks until ctx is done.
func Run(parent context.Context, cfg Config, log *slog.Logger) error {
	ctx, fail := context.WithCancelCause(parent)
	defer fail(nil)
	a := &Agent{
		cfg:        cfg,
		log:        log,
		ctx:        ctx,
		fail:       fail,
		zone:       dns.NewZone(),
		endpoints:  make(map[string]*state.Endpoint),
		cursor:     make(map[uint32]uint16),
		watchers:   make(map[uint32]*netWatch),
		withdrawn:  make(map[pubKey]struct{}),
		dirty:      make(chan struct{}, 1),
		netPeers:   make(map[uint32]map[uint16]map[uint16]struct{}),
		grace:      make(map[datapath.NetNode]time.Time),
		peers:      make(map[uint16]store.Node),
		peersRetry: make(chan struct{}, 1),
	}

	// Before anything is touched: a second daemon on a host would take the
	// first one's place in etcd and in the kernel, and only then find the
	// socket taken.
	if c, err := net.DialTimeout("unix", cfg.Socket, time.Second); err == nil {
		c.Close()
		return errors.New("another open6pn daemon is already serving " + cfg.Socket)
	}

	var err error
	if a.dir, err = state.Open(cfg.StateDir); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	st, err := a.dir.Load()
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	a.meta = st
	a.store, err = store.Open(cfg.Store)
	if err != nil {
		return fmt.Errorf("connect to etcd: %w", err)
	}
	defer a.store.Close()

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	cluster, err := a.store.Cluster(cctx, cfg.NodeBits, cfg.MTU)
	cancel()
	if err != nil {
		return fmt.Errorf("cluster configuration: %w", err)
	}
	a.layout, a.mtu = cluster.Layout, cluster.MTU
	if st.NodeBits != 0 && st.NodeBits != a.layout.NodeBits {
		return fmt.Errorf("this host's state was made in a cluster with %d node bits, but this cluster has %d; "+
			"its endpoints' addresses would change. Point it at its own cluster, or remove %s to join this one afresh",
			st.NodeBits, a.layout.NodeBits, cfg.StateDir)
	}
	st.NodeBits = a.layout.NodeBits

	if err := a.join(ctx, st); err != nil {
		return err
	}
	log.Info("joined mesh", "node", a.node.ID, "name", a.node.Name, "endpoint", a.node.Endpoint,
		"layout", a.layout.String(), "mtu", a.mtu)

	a.dp, err = datapath.Open(datapath.Config{
		Layout:     a.layout,
		NodeID:     a.node.ID,
		PrivateKey: a.key,
		ListenPort: cfg.WGPort,
		MTU:        a.mtu,

		PeerThreads: cfg.WGPeerThreads,
		MaxNetNodes: cfg.MaxNetworkHosts,
		LegacyDecap: os.Getenv("OPEN6PN_LEGACY_DECAP") != "",
	})
	if err != nil {
		return fmt.Errorf("datapath: %w", err)
	}
	defer a.dp.Close()

	if err := a.restore(st); err != nil {
		return fmt.Errorf("restore endpoints: %w", err)
	}

	resolver := &dns.Server{
		Zone:      a.zone,
		Layout:    a.layout,
		NodeID:    a.node.ID,
		Domain:    cfg.DNSDomain,
		Upstreams: cfg.DNSUpstreams,
		TTL:       5,
	}
	if err := resolver.Start(net.JoinHostPort(addr.DNS.String(), "53")); err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	defer resolver.Stop()

	if err := datapath.WatchLinkDeletes(ctx, a.linkDeleted, a.checkLinks); err != nil {
		log.Warn("cannot subscribe to link events; relying on periodic checks", "err", err)
	}

	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){a.watchNodes, a.peerSyncLoop, a.publishLoop, a.checkLinksLoop, a.housekeepingLoop} {
		wg.Add(1)
		go func() { defer wg.Done(); loop(ctx) }()
	}
	err = a.serveAPI(ctx)
	wg.Wait()
	a.mu.Lock()
	a.flushMeta()
	a.mu.Unlock()
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return err
}

// stop ends the daemon because this host no longer owns its node ID. Its
// records in etcd are withdrawn on the way out; what is in the kernel stays,
// so its containers keep what connectivity they have.
func (a *Agent) stop(err error) {
	a.gone.Store(true)
	a.fail(err)
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// join registers this host, creating its identity on first start.
func (a *Agent) join(ctx context.Context, st *state.State) error {
	if st.Node == nil {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		st.Node = &state.Node{Name: a.cfg.NodeName, PrivateKey: key.String()}
	}
	key, err := wgtypes.ParseKey(st.Node.PrivateKey)
	if err != nil {
		return fmt.Errorf("state file holds an invalid private key: %w", err)
	}
	a.key = key

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	node, err := a.store.RegisterNode(rctx, store.Node{
		ID:        st.Node.ID,
		Name:      a.cfg.NodeName,
		PublicKey: key.PublicKey().String(),
		Endpoint:  netip.AddrPortFrom(a.cfg.Advertise, uint16(a.cfg.WGPort)).String(),
	})
	if err != nil {
		return fmt.Errorf("register node: %w", err)
	}
	a.node = node
	st.Node.ID, st.Node.Name = node.ID, node.Name
	// Endpoint addresses embed the node ID, so the ID must survive restarts:
	// persist it before doing anything else.
	if err := a.dir.Save(st); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}

// restore replays the state directory into the kernel after a restart.
func (a *Agent) restore(st *state.State) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	eps, bad, err := a.dir.Endpoints()
	if err != nil {
		return err
	}
	for _, err := range bad {
		a.log.Error("unreadable endpoint state; ignoring it", "err", err)
	}
	// After a reboot none of the interfaces can be the ones that were
	// attached, even where an index and a name happen to match again.
	boot := bootID()
	rebooted := st.BootID != "" && boot != "" && st.BootID != boot
	for network, next := range st.Cursors {
		a.cursor[network] = next
	}

	var keep []datapath.Endpoint
	for i := range eps {
		ep := eps[i]
		dpe, err := dpEndpoint(&ep)
		switch {
		case err != nil:
		case rebooted:
			err = errors.New("the host has rebooted")
		case !datapath.LinkIs(ep.Ifindex, ep.HostIf, dpe.HostMAC):
			err = errors.New("interface is gone")
		default:
			err = a.dp.AttachEndpoint(dpe)
		}
		if err != nil {
			a.log.Warn("dropping endpoint", "id", ep.ID, "if", ep.HostIf, "err", err)
			a.withdrawn[pubKey{ep.NetworkID, ep.EpID}] = struct{}{}
			if err := a.dir.DeleteEndpoint(ep.ID); err != nil {
				return err
			}
			continue
		}
		keep = append(keep, dpe)
		a.endpoints[ep.ID] = &ep
		a.zone.Set(ep.NetworkID, dns.Record{Node: a.node.ID, Ep: ep.EpID}, ep.Names)
		a.retainNetwork(ep.NetworkID, identityOf(&ep))
	}
	if err := a.dp.Prune(keep); err != nil {
		return err
	}

	// What an earlier run allowed stays allowed for the grace period, for
	// the networks still served; the watches confirm or replace it.
	allowed, err := a.dp.AllowedNodes()
	if err != nil {
		return err
	}
	for _, k := range allowed {
		if a.watchers[k.NetID] != nil {
			a.grace[k] = time.Now().Add(peerGrace)
		} else if err := a.dp.DenyNode(k); err != nil {
			return err
		}
	}

	a.log.Info("restored endpoints", "count", len(keep), "dropped", len(eps)-len(keep))
	st.BootID = boot
	return a.flushMeta()
}

// flushMeta writes state.json. Callers hold a.mu.
func (a *Agent) flushMeta() error {
	a.meta.Cursors = make(map[uint32]uint16, len(a.cursor))
	for network, next := range a.cursor {
		a.meta.Cursors[network] = next
	}
	a.metaDirty = false
	return a.dir.Save(a.meta)
}

// identityOf is the network an endpoint was attached to, as far as this host
// recorded it.
func identityOf(ep *state.Endpoint) store.NetworkIdentity {
	return store.Network{Name: ep.NetworkName, CreatedAt: ep.NetworkCreated}.Identity()
}

func dpEndpoint(ep *state.Endpoint) (datapath.Endpoint, error) {
	hmac, err1 := net.ParseMAC(ep.HostMAC)
	cmac, err2 := net.ParseMAC(ep.ContainerMAC)
	if err := errors.Join(err1, err2); err != nil {
		return datapath.Endpoint{}, err
	}
	return datapath.Endpoint{
		NetworkID:    ep.NetworkID,
		EpID:         ep.EpID,
		Ifindex:      ep.Ifindex,
		HostMAC:      hmac,
		ContainerMAC: cmac,
	}, nil
}

// ---- peers ----

// The node list in etcd is the desired set of WireGuard peers. Changes are
// applied one at a time as they arrive; the whole set is reconciled when the
// list is (re)read, after any failed update, and every few minutes regardless.

func (a *Agent) watchNodes(ctx context.Context) {
	a.store.WatchNodes(ctx,
		func(nodes []store.Node) {
			a.peersMu.Lock()
			defer a.peersMu.Unlock()
			a.peers = make(map[uint16]store.Node, len(nodes))
			var self *store.Node
			for _, n := range nodes {
				if n.ID == a.node.ID {
					self = &n
					continue
				}
				a.peers[n.ID] = n
			}
			a.peersKnown = true
			if !a.stillSelf(self) {
				return
			}
			a.syncPeers(true)
		},
		func(n store.Node) {
			if n.ID == a.node.ID {
				a.stillSelf(&n)
				return
			}
			a.peersMu.Lock()
			defer a.peersMu.Unlock()
			old, had := a.peers[n.ID]
			a.peers[n.ID] = n
			if had && old.SamePeer(n) {
				// Its daemon restarted. Reconfiguring the peer would
				// throw the session away for nothing.
				return
			}
			p, err := toPeer(n)
			if err != nil {
				a.log.Warn("ignoring node", "node", n.ID, "err", err)
				if had {
					a.removePeer(old)
				}
				return
			}
			if had && old.PublicKey != n.PublicKey {
				a.removePeer(old)
			}
			if err := a.dp.SetPeer(p); err != nil {
				a.log.Error("set wireguard peer", "node", n.ID, "err", err)
				a.retryPeers()
				return
			}
			a.log.Debug("peer updated", "node", n.ID, "endpoint", n.Endpoint)
		},
		func(id uint16) {
			if id == a.node.ID {
				a.stillSelf(nil)
				return
			}
			a.forgetNode(id)
			a.peersMu.Lock()
			defer a.peersMu.Unlock()
			if old, ok := a.peers[id]; ok {
				delete(a.peers, id)
				a.removePeer(old)
				a.log.Debug("peer removed", "node", id)
			}
		})
}

// stillSelf checks this host's own record in the node list, nil if it has
// none. If the record is not the one this daemon wrote, the daemon stops:
// carrying on would mean two hosts publishing under one node ID.
func (a *Agent) stillSelf(n *store.Node) bool {
	switch {
	case n == nil:
		a.stop(fmt.Errorf("node %d was removed from the mesh while this daemon was running; "+
			"start it again to rejoin, or stop it for good", a.node.ID))
	case n.PublicKey != a.node.PublicKey:
		a.stop(fmt.Errorf("node ID %d now belongs to another host (%s, %s)", n.ID, n.Name, n.Endpoint))
	default:
		return true
	}
	return false
}

// syncPeers makes WireGuard's peers equal to a.peers. It always logs when it
// had to change something, and with report also when it did not. Callers
// hold a.peersMu.
func (a *Agent) syncPeers(report bool) {
	peers := make([]datapath.Peer, 0, len(a.peers))
	for _, n := range a.peers {
		p, err := toPeer(n)
		if err != nil {
			a.log.Warn("ignoring node", "node", n.ID, "err", err)
			continue
		}
		peers = append(peers, p)
	}
	start := time.Now()
	changed, err := a.dp.SyncPeers(peers)
	if err != nil {
		a.log.Error("sync wireguard peers", "err", err)
		a.retryPeers()
		return
	}
	if changed > 0 || report {
		a.log.Info("synced peers", "count", len(peers), "changed", changed, "took", time.Since(start).Round(time.Millisecond))
	}
}

func (a *Agent) retryPeers() {
	select {
	case a.peersRetry <- struct{}{}:
	default:
	}
}

func (a *Agent) peerSyncLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.peersRetry:
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
		a.peersMu.Lock()
		if a.peersKnown {
			a.syncPeers(false)
		}
		a.peersMu.Unlock()
	}
}

func (a *Agent) removePeer(n store.Node) {
	key, err := wgtypes.ParseKey(n.PublicKey)
	if err != nil {
		return
	}
	if err := a.dp.RemovePeer(key); err != nil {
		a.log.Error("remove wireguard peer", "node", n.ID, "err", err)
		a.retryPeers()
	}
}

func toPeer(n store.Node) (datapath.Peer, error) {
	key, err := wgtypes.ParseKey(n.PublicKey)
	if err != nil {
		return datapath.Peer{}, fmt.Errorf("public key: %w", err)
	}
	ap, err := netip.ParseAddrPort(n.Endpoint)
	if err != nil {
		return datapath.Peer{}, fmt.Errorf("endpoint: %w", err)
	}
	return datapath.Peer{NodeID: n.ID, PublicKey: key, Endpoint: net.UDPAddrFromAddrPort(ap)}, nil
}

// ---- endpoints ----

// Attach puts a container interface on a network.
func (a *Agent) Attach(ctx context.Context, req api.AttachRequest) (api.Endpoint, error) {
	ep, ready, err := a.attach(ctx, req)
	if err != nil {
		return ep, err
	}
	// The container can send to other hosts once this host knows which of
	// them serve its network. That takes one read from etcd when the
	// network is new to this host; give it a moment, so that the endpoint
	// is usable when the caller hears about it.
	select {
	case <-ready:
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	return ep, nil
}

func (a *Agent) attach(ctx context.Context, req api.AttachRequest) (api.Endpoint, <-chan struct{}, error) {
	var names []string
	for _, raw := range req.Names {
		n, err := dns.NormalizeName(raw)
		if err != nil {
			return api.Endpoint{}, nil, badRequest(err)
		}
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	var cmac net.HardwareAddr
	if req.ContainerMAC != "" {
		var err error
		if cmac, err = net.ParseMAC(req.ContainerMAC); err != nil || len(cmac) != 6 {
			return api.Endpoint{}, nil, badRequest(fmt.Errorf("invalid container MAC address %q", req.ContainerMAC))
		}
	}
	if req.Netns == "" && req.HostIf == "" {
		return api.Endpoint{}, nil, badRequest(errors.New("give a network namespace, a host veth, or both"))
	}

	network, err := a.resolveNetwork(ctx, req.Network)
	if err != nil {
		return api.Endpoint{}, nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if req.HostIf != "" {
		for _, ep := range a.endpoints {
			if ep.HostIf == req.HostIf {
				return api.Endpoint{}, nil, fmt.Errorf("%s is already attached to network %s: %w", req.HostIf, ep.NetworkName, store.ErrExists)
			}
		}
	}
	// The same ID under another name or creation time is another network.
	// That cannot happen while etcd keeps its history, and must not be
	// papered over if it does: the two would share one address space.
	for _, ep := range a.endpoints {
		if ep.NetworkID != network.ID {
			continue
		}
		if !identityOf(ep).Same(network.Identity()) {
			return api.Endpoint{}, nil, fmt.Errorf("network ID %d is %q in etcd, but this host has endpoints of %q attached under that ID; "+
				"has etcd been restored from a backup? Refusing to put both in one network", network.ID, network.Name, ep.NetworkName)
		}
		break
	}
	epID, err := a.allocEndpoint(network.ID)
	if err != nil {
		return api.Endpoint{}, nil, err
	}

	veth, err := datapath.SetupVeth(datapath.VethRequest{
		HostIf:       req.HostIf,
		Netns:        req.Netns,
		ContainerIf:  req.ContainerIf,
		ContainerMAC: cmac,
		V6:           addr.V6(a.node.ID, network.ID, epID),
		V4:           a.layout.V4(a.node.ID, epID),
		MTU:          a.containerMTU(),
	})
	if err != nil {
		return api.Endpoint{}, nil, badRequest(err)
	}
	ep := &state.Endpoint{
		ID:             newID(),
		NetworkID:      network.ID,
		NetworkName:    network.Name,
		NetworkCreated: network.CreatedAt,
		EpID:           epID,
		Names:          names,
		HostIf:         veth.HostIf,
		Ifindex:        veth.Ifindex,
		HostMAC:        veth.HostMAC.String(),
		ContainerMAC:   veth.ContainerMAC.String(),
		Created:        veth.Created,
		AttachedAt:     time.Now().UTC().Truncate(time.Second),
	}
	dpe, _ := dpEndpoint(ep)
	undo := func() {
		a.dp.DetachEndpoint(dpe)
		if veth.Created {
			datapath.DeleteVeth(veth.Ifindex, veth.HostIf)
		}
	}
	if err := a.dp.AttachEndpoint(dpe); err != nil {
		undo()
		return api.Endpoint{}, nil, fmt.Errorf("program datapath: %w", err)
	}
	if err := a.dir.SaveEndpoint(ep); err != nil {
		undo()
		return api.Endpoint{}, nil, fmt.Errorf("save state: %w", err)
	}
	// The allocation position goes to disk with the endpoint, not later:
	// a daemon that is killed must not hand the same addresses out again.
	if err := a.flushMeta(); err != nil {
		a.dir.DeleteEndpoint(ep.ID)
		undo()
		return api.Endpoint{}, nil, fmt.Errorf("save state: %w", err)
	}
	a.endpoints[ep.ID] = ep

	delete(a.withdrawn, pubKey{network.ID, epID})
	a.zone.Set(network.ID, dns.Record{Node: a.node.ID, Ep: epID}, names)
	a.retainNetwork(network.ID, identityOf(ep))
	a.kick()
	a.log.Info("attached", "id", ep.ID, "network", network.Name, "if", ep.HostIf, "ipv6", addr.V6(a.node.ID, network.ID, epID))
	return a.describe(ep, true), a.watchers[network.ID].ready, nil
}

// Detach removes an endpoint, named by ID or host interface.
func (a *Agent) Detach(ref string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ep := a.endpoints[ref]
	if ep == nil {
		for _, e := range a.endpoints {
			if e.HostIf == ref {
				ep = e
				break
			}
		}
	}
	if ep == nil {
		return fmt.Errorf("endpoint %s: %w", ref, store.ErrNotFound)
	}
	return a.remove(ep, "detached")
}

// remove tears an endpoint down. Callers hold a.mu.
func (a *Agent) remove(ep *state.Endpoint, why string) error {
	if dpe, err := dpEndpoint(ep); err == nil {
		if err := a.dp.DetachEndpoint(dpe); err != nil {
			a.log.Warn("detach from datapath", "id", ep.ID, "err", err)
		}
	}
	if ep.Created {
		datapath.DeleteVeth(ep.Ifindex, ep.HostIf)
	}
	delete(a.endpoints, ep.ID)
	a.zone.Delete(ep.NetworkID, dns.Record{Node: a.node.ID, Ep: ep.EpID})
	a.withdrawn[pubKey{ep.NetworkID, ep.EpID}] = struct{}{}
	a.releaseNetwork(ep.NetworkID)
	a.kick()
	a.log.Info(why, "id", ep.ID, "network", ep.NetworkName, "if", ep.HostIf)
	return a.dir.DeleteEndpoint(ep.ID)
}

// Endpoints lists the endpoints on this host.
func (a *Agent) Endpoints() []api.Endpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]api.Endpoint, 0, len(a.endpoints))
	for _, ep := range a.endpoints {
		out = append(out, a.describe(ep, false))
	}
	slices.SortFunc(out, func(x, y api.Endpoint) int {
		if x.NetworkID != y.NetworkID {
			return int(int64(x.NetworkID) - int64(y.NetworkID))
		}
		return int(x.EndpointID) - int(y.EndpointID)
	})
	return out
}

func (a *Agent) describe(ep *state.Endpoint, full bool) api.Endpoint {
	out := api.Endpoint{
		ID:         ep.ID,
		Network:    ep.NetworkName,
		NetworkID:  ep.NetworkID,
		NodeID:     a.node.ID,
		EndpointID: ep.EpID,
		IPv6:       addr.V6(a.node.ID, ep.NetworkID, ep.EpID).String(),
		IPv4:       a.layout.V4(a.node.ID, ep.EpID).String(),
		Names:      ep.Names,
		HostIf:     ep.HostIf,
		AttachedAt: ep.AttachedAt,
	}
	if full {
		out.MTU = a.containerMTU()
		out.Routes = []api.Route{
			{Dst: addr.Cluster6.String(), Via: addr.Gateway6.String()},
			{Dst: addr.Cluster4.String(), Via: addr.Gateway4.String()},
		}
		out.DNS = &api.DNSConfig{Servers: []string{addr.DNS.String()}, Search: []string{a.cfg.DNSDomain}}
	}
	return out
}

// The container MTU leaves room for the IPv6 header that IPv4 packets gain
// between hosts.
func (a *Agent) containerMTU() int { return a.mtu - datapath.EncapOverhead }

// allocEndpoint picks a free endpoint ID in a network on this host. It moves
// forward through the range rather than reusing the lowest free ID, so an
// address is not handed to a new container the moment its old one goes away.
// The position is kept in the state file, so that holds across restarts and
// across the network having no endpoints here for a while. Callers hold a.mu.
func (a *Agent) allocEndpoint(network uint32) (uint16, error) {
	used := make(map[uint16]bool)
	for _, ep := range a.endpoints {
		if ep.NetworkID == network {
			used[ep.EpID] = true
		}
	}
	top := a.layout.MaxEndpoint()
	start := a.cursor[network]
	if start == 0 {
		start = 1
		for id := range used {
			if id >= start && id < top {
				start = id + 1
			}
		}
	}
	for i := range top {
		id := (start-1+i)%top + 1
		if !used[id] {
			a.cursor[network] = id%top + 1
			a.metaDirty = true
			return id, nil
		}
	}
	return 0, fmt.Errorf("this host already has %d endpoints in network %d, the most the cluster's address layout allows; "+
		"place the container on another host", top, network)
}

// resolveNetwork finds a network by name or ID. etcd decides; if it cannot be
// reached, a network this host already has endpoints in is still usable.
func (a *Agent) resolveNetwork(ctx context.Context, ref string) (store.Network, error) {
	if ref == "" {
		return store.Network{}, badRequest(errors.New("network is required"))
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := a.store.GetNetwork(ctx, ref)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		return n, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ep := range a.endpoints {
		if ep.NetworkName == ref || strconv.FormatUint(uint64(ep.NetworkID), 10) == ref {
			return store.Network{ID: ep.NetworkID, Name: ep.NetworkName, CreatedAt: ep.NetworkCreated}, nil
		}
	}
	return store.Network{}, fmt.Errorf("look up network %s: %w", ref, err)
}

// ---- other hosts' endpoints ----

// retainNetwork starts following a network's endpoints on other hosts when
// the first local endpoint joins it. Callers hold a.mu.
func (a *Agent) retainNetwork(network uint32, identity store.NetworkIdentity) {
	if w := a.watchers[network]; w != nil {
		w.refs++
		return
	}
	ctx, cancel := context.WithCancel(a.ctx)
	w := &netWatch{refs: 1, cancel: cancel, ready: make(chan struct{}), identity: identity}
	a.watchers[network] = w

	// ours reports whether a record is for the network this host has under
	// the ID. Called with a.mu held.
	ours := func(ep store.Endpoint) bool {
		if w.identity.Same(ep.Network) {
			return true
		}
		if !w.foreign {
			w.foreign = true
			a.log.Error("another host has endpoints of a different network under this network's ID; ignoring them. "+
				"Has etcd been restored from a backup?", "network_id", network, "here", w.identity.Name,
				"there", ep.Network.Name, "node", ep.NodeID)
		}
		return false
	}

	// Updates are applied only while this watch is still the current one,
	// so nothing trickles in after the network has been released.
	apply := func(fn func()) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.watchers[network] == w {
			fn()
		}
	}
	self := a.node.ID
	go a.store.WatchEndpoints(ctx, network,
		func(all []store.Endpoint) {
			apply(func() {
				eps := make([]store.Endpoint, 0, len(all))
				m := make(map[dns.Record][]string, len(all))
				for _, ep := range all {
					if ep.NodeID == self || ours(ep) {
						eps = append(eps, ep)
						m[dns.Record{Node: ep.NodeID, Ep: ep.EpID}] = ep.Names
					}
				}
				a.zone.ReplaceRemote(network, self, m)
				a.replacePeers(network, eps)
			})
			w.readyOnce.Do(func() { close(w.ready) })
		},
		func(ep store.Endpoint) {
			if ep.NodeID != self {
				apply(func() {
					if !ours(ep) {
						// Whatever this record was before, it is not ours now.
						a.zone.Delete(network, dns.Record{Node: ep.NodeID, Ep: ep.EpID})
						a.delPeerEndpoint(network, ep.NodeID, ep.EpID)
						return
					}
					a.zone.Set(network, dns.Record{Node: ep.NodeID, Ep: ep.EpID}, ep.Names)
					a.addPeerEndpoint(network, ep.NodeID, ep.EpID)
				})
			}
		},
		func(ep store.Endpoint) {
			if ep.NodeID != self {
				apply(func() {
					a.zone.Delete(network, dns.Record{Node: ep.NodeID, Ep: ep.EpID})
					a.delPeerEndpoint(network, ep.NodeID, ep.EpID)
				})
			}
		})
}

// ---- which hosts a network's containers may send to ----
//
// A container can address any host: the node is part of the address. The
// datapath only lets it send to hosts that have an endpoint in its network,
// which this keeps up to date from the same records the resolver uses.
// Callers of everything here hold a.mu.

func (a *Agent) allowNode(network uint32, node uint16) {
	k := datapath.NetNode{NetID: network, Node: uint32(node)}
	delete(a.grace, k)
	err := a.dp.AllowNode(k)
	if err == nil {
		return
	}
	if errors.Is(err, datapath.ErrNetNodesFull) {
		// Once a minute is enough: when it is full, it is full for many.
		if time.Since(a.fullLogged) < time.Minute {
			return
		}
		a.fullLogged = time.Now()
		a.log.Error("containers cannot send to some hosts: the table of hosts per network is full; "+
			"raise --max-network-hosts and restart the daemon", "network", network, "node", node)
		return
	}
	a.log.Error("allow sending to a node", "network", network, "node", node, "err", err)
}

func (a *Agent) denyNode(k datapath.NetNode) {
	delete(a.grace, k)
	if err := a.dp.DenyNode(k); err != nil {
		a.log.Error("stop sending to a node", "network", k.NetID, "node", k.Node, "err", err)
	}
}

func (a *Agent) addPeerEndpoint(network uint32, node, ep uint16) {
	nodes := a.netPeers[network]
	if nodes == nil {
		nodes = make(map[uint16]map[uint16]struct{})
		a.netPeers[network] = nodes
	}
	if nodes[node] == nil {
		nodes[node] = make(map[uint16]struct{})
		a.allowNode(network, node)
	}
	nodes[node][ep] = struct{}{}
}

func (a *Agent) delPeerEndpoint(network uint32, node, ep uint16) {
	eps := a.netPeers[network][node]
	if eps == nil {
		return
	}
	if delete(eps, ep); len(eps) == 0 {
		delete(a.netPeers[network], node)
		a.grace[datapath.NetNode{NetID: network, Node: uint32(node)}] = time.Now().Add(peerGrace)
	}
}

// replacePeers makes a network's allowed nodes those that eps names. Nodes
// that were allowed and are not named go into grace.
func (a *Agent) replacePeers(network uint32, eps []store.Endpoint) {
	old := a.netPeers[network]
	now := make(map[uint16]map[uint16]struct{})
	for _, ep := range eps {
		if ep.NodeID == a.node.ID {
			continue
		}
		if now[ep.NodeID] == nil {
			now[ep.NodeID] = make(map[uint16]struct{})
			// Whether or not it was allowed before: the map in the
			// kernel may have been emptied since.
			a.allowNode(network, ep.NodeID)
		}
		now[ep.NodeID][ep.EpID] = struct{}{}
	}
	for node := range old {
		if now[node] == nil {
			a.grace[datapath.NetNode{NetID: network, Node: uint32(node)}] = time.Now().Add(peerGrace)
		}
	}
	a.netPeers[network] = now
}

// forgetNode stops all sending to a node that has left the mesh.
func (a *Agent) forgetNode(node uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Every network served here, not only those the node is known in: the
	// datapath may have let it in by itself since the last look.
	for network := range a.watchers {
		delete(a.netPeers[network], node)
		a.denyNode(datapath.NetNode{NetID: network, Node: uint32(node)})
	}
	for k := range a.grace {
		if k.Node == uint32(node) {
			a.denyNode(k)
		}
	}
}

// adoptLearnedNodes takes charge of the nodes the datapath allowed by itself,
// on receiving traffic from them, and that etcd has not confirmed: they get
// the grace period like any other node that is no longer known to be there.
// allowed is the datapath's table as read a moment ago, without the lock:
// reading it takes too long to hold everything else up.
func (a *Agent) adoptLearnedNodes(allowed []datapath.NetNode) {
	for _, k := range allowed {
		if a.watchers[k.NetID] == nil {
			a.denyNode(k)
			continue
		}
		if _, waiting := a.grace[k]; !waiting && k.Node <= 0xffff && a.netPeers[k.NetID][uint16(k.Node)] == nil {
			a.grace[k] = time.Now().Add(peerGrace)
		}
	}
}

// housekeepingLoop ends grace periods and writes out state that can wait.
func (a *Agent) housekeepingLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	a.repairTick = mrand.IntN(20) // hosts must not all ask at once
	for tick := 1; ; tick++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var learned []datapath.NetNode
		if tick%10 == 0 {
			var err error
			if learned, err = a.dp.AllowedNodes(); err != nil {
				a.log.Warn("cannot read the allowed nodes", "err", err)
			}
		}
		// etcd may have been restored from a backup without this daemon
		// noticing: its lease can survive that.
		if tick%20 == a.repairTick {
			a.repairNetworkCounter(ctx)
		}
		a.mu.Lock()
		a.adoptLearnedNodes(learned)
		now := time.Now()
		for k, until := range a.grace {
			if now.After(until) {
				a.denyNode(k)
			}
		}
		if a.metaDirty {
			if err := a.flushMeta(); err != nil {
				a.log.Error("save state", "err", err)
			}
		}
		a.mu.Unlock()
	}
}

// releaseNetwork stops following a network when the last local endpoint
// leaves it. Callers hold a.mu.
func (a *Agent) releaseNetwork(network uint32) {
	w := a.watchers[network]
	if w == nil {
		return
	}
	if w.refs--; w.refs > 0 {
		return
	}
	w.cancel()
	delete(a.watchers, network)
	a.zone.Drop(network)
	for node := range a.netPeers[network] {
		a.denyNode(datapath.NetNode{NetID: network, Node: uint32(node)})
	}
	delete(a.netPeers, network)
	for k := range a.grace {
		if k.NetID == network {
			a.denyNode(k)
		}
	}
	// The cursor stays, so that the network's addresses are not reused at
	// once if it comes back. Only so many are kept.
	if len(a.cursor) > maxCursors {
		for n := range a.cursor {
			if a.watchers[n] == nil {
				delete(a.cursor, n)
				if len(a.cursor) <= maxCursors/2 {
					break
				}
			}
		}
		a.metaDirty = true
	}
}

// ---- publishing local endpoints ----

func (a *Agent) kick() {
	select {
	case a.dirty <- struct{}{}:
	default:
	}
}

// publishLoop keeps etcd's view of this host's endpoints equal to the local
// one. Records hang off a lease; if the lease is ever lost, a new one is
// taken and everything is published again.
func (a *Agent) publishLoop(ctx context.Context) {
	for ctx.Err() == nil {
		lease, lost, err := a.store.Lease(ctx, a.cfg.EndpointTTL)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("cannot get an etcd lease; retrying", "err", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			continue
		}
		// A new lease means this is a start, or contact with etcd was
		// lost for a while. Either way etcd may not be the etcd it was.
		a.repairNetworkCounter(ctx)
		published := make(map[pubKey]string)
		retry := time.NewTicker(15 * time.Second)
	session:
		for {
			a.publish(ctx, lease, published)
			select {
			case <-ctx.Done():
				retry.Stop()
				if a.gone.Load() {
					// This host is out of the mesh: take its records
					// with it now rather than when the lease runs out.
					rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := a.store.Revoke(rctx, lease); err != nil {
						a.log.Warn("could not withdraw this host's records; they expire with their lease", "err", err)
					}
					cancel()
				}
				return
			case <-lost:
				a.log.Warn("etcd lease lost; republishing endpoints")
				break session
			case <-a.dirty:
			case <-retry.C:
			}
		}
		retry.Stop()
	}
}

// repairNetworkCounter puts etcd's network ID counter back above every
// network this host has endpoints in. See store.RaiseNetworkCounter.
func (a *Agent) repairNetworkCounter(ctx context.Context) {
	a.mu.Lock()
	var top uint32
	for _, ep := range a.endpoints {
		top = max(top, ep.NetworkID)
	}
	a.mu.Unlock()
	if top == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raised, err := a.store.RaiseNetworkCounter(rctx, top)
	if err != nil {
		a.log.Warn("could not check the network ID counter", "err", err)
	} else if raised {
		a.log.Error("etcd's network ID counter was at or below a network this host has containers in, and has been moved past it; "+
			"if etcd was restored from a backup, check that no network was created in between", "network", top)
	}
}

func (a *Agent) publish(ctx context.Context, lease int64, published map[pubKey]string) {
	a.mu.Lock()
	want := make(map[pubKey][]string, len(a.endpoints))
	identity := make(map[pubKey]store.NetworkIdentity, len(a.endpoints))
	for _, ep := range a.endpoints {
		want[pubKey{ep.NetworkID, ep.EpID}] = ep.Names
		identity[pubKey{ep.NetworkID, ep.EpID}] = identityOf(ep)
	}
	gone := make([]pubKey, 0, len(a.withdrawn))
	for k := range a.withdrawn {
		gone = append(gone, k)
	}
	a.mu.Unlock()

	for _, k := range gone {
		octx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.store.DeleteEndpoint(octx, k.net, a.node.ID, k.ep)
		cancel()
		if err != nil {
			return // etcd is unreachable; the ticker brings us back
		}
		delete(published, k)
		a.mu.Lock()
		// Unless it was attached again in the meantime.
		if _, again := want[k]; !again {
			delete(a.withdrawn, k)
		}
		a.mu.Unlock()
	}
	for k, names := range want {
		sig := strings.Join(names, ",")
		if cur, ok := published[k]; ok && cur == sig {
			continue
		}
		octx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.store.PutEndpoint(octx, store.Endpoint{NetworkID: k.net, NodeID: a.node.ID, EpID: k.ep, Names: names, Network: identity[k]}, lease)
		cancel()
		if err != nil {
			return
		}
		published[k] = sig
	}
}

// ---- interfaces that vanish ----

// A container that exits takes its veth with it. That is treated as a detach.
func (a *Agent) linkDeleted(ifindex int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ep := range a.endpoints {
		if ep.Ifindex == ifindex {
			if err := a.remove(ep, "interface gone; detached"); err != nil {
				a.log.Error("save state", "err", err)
			}
			return
		}
	}
}

// checkLinksLoop catches deletions whose notification was lost.
func (a *Agent) checkLinksLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.checkLinks()
	}
}

// checkLinks detaches every endpoint whose interface no longer exists.
func (a *Agent) checkLinks() {
	// Only endpoints that existed before the interfaces are listed can be
	// judged by the list, and listing them is too slow to do under the lock.
	a.mu.Lock()
	before := make(map[string]int, len(a.endpoints))
	for id, ep := range a.endpoints {
		before[id] = ep.Ifindex
	}
	a.mu.Unlock()
	if len(before) == 0 {
		return
	}
	names, err := datapath.LinkNames()
	if err != nil {
		a.log.Warn("cannot list interfaces", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, ifindex := range before {
		ep := a.endpoints[id]
		if ep == nil || ep.Ifindex != ifindex || names[ifindex] == ep.HostIf {
			continue
		}
		if err := a.remove(ep, "interface gone; detached"); err != nil {
			a.log.Error("save state", "err", err)
		}
	}
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
