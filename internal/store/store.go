// Package store is the cluster state in etcd.
//
//	<prefix>/config                             the address layout; written once
//	<prefix>/nodes/<id>                         a host: ID, WireGuard key, address
//	<prefix>/networks/name/<name>               a private network
//	<prefix>/networks/id/<id>                   its name, for lookups by ID
//	<prefix>/networks/next                      the next network ID; never goes back
//	<prefix>/endpoints/<network>/<node>/<ep>    an attached interface and its DNS names
//
// Nodes and networks are permanent until removed. Endpoint keys are bound to a
// lease held by the daemon that owns them, so they disappear with their host.
//
// Every host watches the node list. A host watches a network's endpoints only
// while it has an endpoint of its own in that network, so the cost of a
// change is proportional to the hosts that network actually runs on.
package store

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"open6pn/internal/addr"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInUse    = errors.New("in use")
)

// DefaultMTU is the WireGuard MTU of a cluster that does not say otherwise.
const DefaultMTU = 1420

// Cluster is what every host of a cluster must agree on. It is written once,
// by the first host.
type Cluster struct {
	addr.Layout
	// MTU of the WireGuard device. A host with a larger one would send
	// packets the others cannot deliver, and nothing would tell the sender.
	MTU int `json:"mtu,omitempty"`
}

// Node is a host in the mesh.
type Node struct {
	ID        uint16 `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"` // ip:port of its WireGuard socket
}

// SamePeer reports whether two records describe the same WireGuard peer.
func (n Node) SamePeer(o Node) bool {
	return n.ID == o.ID && n.PublicKey == o.PublicKey && n.Endpoint == o.Endpoint
}

// Network is a private network.
type Network struct {
	ID        uint32    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Endpoint is an attached interface as other hosts see it.
type Endpoint struct {
	NetworkID uint32   `json:"network_id"`
	NodeID    uint16   `json:"node_id"`
	EpID      uint16   `json:"endpoint_id"`
	Names     []string `json:"names,omitempty"`
	// Network says which network the publishing host means by NetworkID.
	// IDs are unique as long as etcd keeps its history; if it does not,
	// two networks can end up with one ID, and this is how hosts tell
	// their endpoints apart. Not shown by the API.
	Network NetworkIdentity `json:"-"`
}

// NetworkIdentity is what makes a network that network, beyond its ID.
type NetworkIdentity struct {
	Name    string `json:"name,omitempty"`
	Created int64  `json:"created,omitempty"` // Unix seconds
}

// Identity returns the network's identity.
func (n Network) Identity() NetworkIdentity {
	id := NetworkIdentity{Name: n.Name}
	if !n.CreatedAt.IsZero() {
		id.Created = n.CreatedAt.Unix()
	}
	return id
}

// Same reports whether two identities can be the same network. A part that
// either side does not know is not held against it.
func (a NetworkIdentity) Same(b NetworkIdentity) bool {
	if a.Name != "" && b.Name != "" && a.Name != b.Name {
		return false
	}
	return a.Created == 0 || b.Created == 0 || a.Created == b.Created
}

// Config says how to reach etcd.
type Config struct {
	Endpoints []string
	Prefix    string
	Username  string
	Password  string
	TLS       *tls.Config
}

// Store is a connection to the cluster state.
type Store struct {
	cli    *clientv3.Client
	prefix string
	layout addr.Layout // set by Cluster
}

// Open connects to etcd.
func Open(cfg Config) (*Store, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:            cfg.Endpoints,
		Username:             cfg.Username,
		Password:             cfg.Password,
		TLS:                  cfg.TLS,
		DialTimeout:          5 * time.Second,
		DialKeepAliveTime:    10 * time.Second,
		DialKeepAliveTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &Store{cli: cli, prefix: "/" + strings.Trim(cfg.Prefix, "/")}, nil
}

// Close closes the connection.
func (s *Store) Close() error { return s.cli.Close() }

func (s *Store) configKey() string          { return s.prefix + "/config" }
func (s *Store) nodesPrefix() string        { return s.prefix + "/nodes/" }
func (s *Store) nodeKey(id uint16) string   { return fmt.Sprintf("%s%05d", s.nodesPrefix(), id) }
func (s *Store) netNamePrefix() string      { return s.prefix + "/networks/name/" }
func (s *Store) netNameKey(n string) string { return s.netNamePrefix() + n }
func (s *Store) netIDKey(id uint32) string  { return fmt.Sprintf("%s/networks/id/%d", s.prefix, id) }
func (s *Store) netNextKey() string         { return s.prefix + "/networks/next" }
func (s *Store) endpointsPrefix(network uint32) string {
	return fmt.Sprintf("%s/endpoints/%d/", s.prefix, network)
}
func (s *Store) endpointKey(network uint32, node, ep uint16) string {
	return fmt.Sprintf("%s%d/%d", s.endpointsPrefix(network), node, ep)
}

// ---- cluster ----

// Cluster returns the cluster's configuration, creating the cluster with
// nodeBits and mtu (or the defaults, where zero) when this is its first host.
// A non-zero value that disagrees with an existing cluster is an error: the
// layout is part of every address and cannot change under running containers,
// and hosts with different MTUs silently lose each other's large packets.
//
// Cluster must be called before anything else; the layout decides which node
// and endpoint IDs are valid.
func (s *Store) Cluster(ctx context.Context, nodeBits, mtu int) (Cluster, error) {
	want := Cluster{Layout: addr.DefaultLayout, MTU: DefaultMTU}
	if nodeBits != 0 {
		want.Layout = addr.Layout{NodeBits: nodeBits}
	}
	if mtu != 0 {
		want.MTU = mtu
	}
	if err := want.Validate(); err != nil {
		return Cluster{}, err
	}
	key := s.configKey()
	txn, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, mustJSON(want))).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return Cluster{}, err
	}
	have := want
	if !txn.Succeeded {
		have = Cluster{}
		kvs := txn.Responses[0].GetResponseRange().Kvs
		if len(kvs) != 1 || json.Unmarshal(kvs[0].Value, &have) != nil || have.Validate() != nil {
			return Cluster{}, fmt.Errorf("corrupt cluster configuration at %s", key)
		}
		if nodeBits != 0 && have.Layout != want.Layout {
			return Cluster{}, fmt.Errorf("this cluster was created with %d node bits; it cannot be changed to %d", have.NodeBits, nodeBits)
		}
		if have.MTU == 0 {
			// A cluster from before the MTU was recorded. The first host
			// to come along records its own; if another gets there first,
			// read again and be held to that one.
			have.MTU = want.MTU
			set, err := s.cli.Txn(ctx).
				If(clientv3.Compare(clientv3.ModRevision(key), "=", kvs[0].ModRevision)).
				Then(clientv3.OpPut(key, mustJSON(have))).
				Commit()
			if err != nil {
				return Cluster{}, err
			}
			if !set.Succeeded {
				return s.Cluster(ctx, nodeBits, mtu)
			}
		}
		if mtu != 0 && have.MTU != mtu {
			return Cluster{}, fmt.Errorf("this cluster was created with an MTU of %d; it cannot be changed to %d on one host", have.MTU, mtu)
		}
	}
	s.layout = have.Layout
	return have, nil
}

// ---- nodes ----

// RegisterNode adds this host to the mesh, or refreshes its record.
//
// A host is recognised by its public key: registering the same key again
// returns the ID it already has. With n.ID zero the lowest free ID is taken.
func (s *Store) RegisterNode(ctx context.Context, n Node) (Node, error) {
attempts:
	for attempt := range 16 {
		kvs, _, err := s.list(ctx, s.nodesPrefix())
		if err != nil {
			return Node{}, err
		}
		used := make(map[uint16]bool, len(kvs))
		for _, kv := range kvs {
			var cur Node
			if err := json.Unmarshal(kv.Value, &cur); err != nil {
				continue
			}
			used[cur.ID] = true
			if cur.PublicKey != n.PublicKey {
				continue
			}
			if n.ID != 0 && n.ID != cur.ID {
				return Node{}, fmt.Errorf("this host's key is registered as node %d, not %d", cur.ID, n.ID)
			}
			n.ID = cur.ID
			if cur == n {
				return n, nil
			}
			// Only if the record is still the one just read: it may have
			// been removed, and the ID given to another host, since.
			txn, err := s.cli.Txn(ctx).
				If(clientv3.Compare(clientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision)).
				Then(clientv3.OpPut(string(kv.Key), mustJSON(n))).
				Commit()
			if err != nil {
				return Node{}, err
			}
			if txn.Succeeded {
				return n, nil
			}
			continue attempts
		}

		id := n.ID
		if id == 0 {
			if id = s.freeNodeID(used, attempt > 0); id == 0 {
				return Node{}, fmt.Errorf("the mesh is full: all %d node IDs are taken", s.layout.MaxNode())
			}
		} else if !s.layout.ValidNode(id) {
			return Node{}, fmt.Errorf("node ID %d is outside this cluster's range of 1-%d", id, s.layout.MaxNode())
		} else if used[id] {
			return Node{}, fmt.Errorf("node ID %d belongs to another host: %w", id, ErrExists)
		}
		reg := n
		reg.ID = id
		key := s.nodeKey(id)
		txn, err := s.cli.Txn(ctx).
			If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
			Then(clientv3.OpPut(key, mustJSON(reg))).
			Commit()
		if err != nil {
			return Node{}, err
		}
		if txn.Succeeded {
			return reg, nil
		}
		// Another host took the ID first; look again.
	}
	return Node{}, errors.New("could not allocate a node ID: too much contention")
}

// freeNodeID returns an unused node ID, or zero if there is none: the lowest
// one, or with scatter a random one. Hosts that join at the same moment all
// see the same lowest free ID and only one of them can have it; the rest
// scatter so that they do not collide again on the next one.
func (s *Store) freeNodeID(used map[uint16]bool, scatter bool) uint16 {
	top := int(s.layout.MaxNode())
	if !scatter {
		for id := 1; id <= top; id++ {
			if !used[uint16(id)] {
				return uint16(id)
			}
		}
		return 0
	}
	free := make([]uint16, 0, top)
	for id := 1; id <= top; id++ {
		if !used[uint16(id)] {
			free = append(free, uint16(id))
		}
	}
	if len(free) == 0 {
		return 0
	}
	return free[rand.N(len(free))]
}

// ListNodes returns every host in the mesh.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	kvs, _, err := s.list(ctx, s.nodesPrefix())
	if err != nil {
		return nil, err
	}
	return s.decodeNodes(kvs), nil
}

// DeleteNode removes a host from the mesh. Other hosts drop it as a peer.
func (s *Store) DeleteNode(ctx context.Context, id uint16) error {
	resp, err := s.cli.Delete(ctx, s.nodeKey(id))
	if err != nil {
		return err
	}
	if resp.Deleted == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// WatchNodes keeps the caller in step with the node list until ctx is done.
// reset replaces everything known so far; put and del are single changes.
func (s *Store) WatchNodes(ctx context.Context, reset func([]Node), put func(Node), del func(id uint16)) {
	s.watch(ctx, s.nodesPrefix(),
		func(kvs []*mvccpb.KeyValue) { reset(s.decodeNodes(kvs)) },
		func(ev *clientv3.Event) {
			if ev.Type == clientv3.EventTypeDelete {
				id, err := strconv.ParseUint(strings.TrimPrefix(string(ev.Kv.Key), s.nodesPrefix()), 10, 16)
				if err == nil {
					del(uint16(id))
				}
				return
			}
			var n Node
			if json.Unmarshal(ev.Kv.Value, &n) == nil && s.layout.ValidNode(n.ID) {
				put(n)
			}
		})
}

func (s *Store) decodeNodes(kvs []*mvccpb.KeyValue) []Node {
	nodes := make([]Node, 0, len(kvs))
	for _, kv := range kvs {
		var n Node
		if json.Unmarshal(kv.Value, &n) == nil && s.layout.ValidNode(n.ID) {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// ---- networks ----

var networkName = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$`)
var allDigits = regexp.MustCompile(`^[0-9]+$`)

// ValidNetworkName reports whether name can be used for a network. Names made
// only of digits are refused because they would be ambiguous with IDs.
func ValidNetworkName(name string) bool {
	return networkName.MatchString(name) && !allDigits.MatchString(name)
}

// CreateNetwork creates a private network with a new, never-before-used ID.
//
// IDs come from a counter that only moves forward. A deleted network's ID is
// not handed out again, so nothing left over from it can ever end up inside
// a later network.
func (s *Store) CreateNetwork(ctx context.Context, name string) (Network, error) {
	if !ValidNetworkName(name) {
		return Network{}, fmt.Errorf("invalid network name %q: use 1-63 of a-z, 0-9, '.', '_', '-', not only digits", name)
	}
	nameKey, nextKey := s.netNameKey(name), s.netNextKey()
	for range 32 {
		resp, err := s.cli.Get(ctx, nextKey)
		if err != nil {
			return Network{}, err
		}
		var id, rev uint64 = 1, 0
		if len(resp.Kvs) == 1 {
			id, err = strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
			if err != nil {
				return Network{}, fmt.Errorf("corrupt network ID counter: %w", err)
			}
			rev = uint64(resp.Kvs[0].ModRevision)
		}
		if id > math.MaxUint32 {
			return Network{}, errors.New("network IDs are exhausted")
		}
		n := Network{ID: uint32(id), Name: name, CreatedAt: time.Now().UTC().Truncate(time.Second)}
		txn, err := s.cli.Txn(ctx).
			If(
				clientv3.Compare(clientv3.CreateRevision(nameKey), "=", 0),
				clientv3.Compare(clientv3.ModRevision(nextKey), "=", int64(rev)),
			).
			Then(
				clientv3.OpPut(nameKey, mustJSON(n)),
				clientv3.OpPut(s.netIDKey(n.ID), name),
				clientv3.OpPut(nextKey, strconv.FormatUint(id+1, 10)),
			).
			Else(clientv3.OpGet(nameKey, clientv3.WithCountOnly())).
			Commit()
		if err != nil {
			return Network{}, err
		}
		if txn.Succeeded {
			return n, nil
		}
		if txn.Responses[0].GetResponseRange().Count > 0 {
			return Network{}, fmt.Errorf("network %q: %w", name, ErrExists)
		}
		// Lost a race for the counter; try the next ID.
	}
	return Network{}, errors.New("could not allocate a network ID: too much contention")
}

// RaiseNetworkCounter makes sure the next network ID handed out is above id.
//
// The counter only moves forward as long as etcd keeps its history. If etcd
// is restored from a backup the counter goes back with it, and a new network
// could be given the ID of one whose containers are still running. Hosts call
// this with the highest ID they have endpoints in whenever they (re)connect,
// which puts the counter back above every ID still in use.
func (s *Store) RaiseNetworkCounter(ctx context.Context, id uint32) (raised bool, err error) {
	key := s.netNextKey()
	want := strconv.FormatUint(uint64(id)+1, 10)
	for range 32 {
		resp, err := s.cli.Get(ctx, key)
		if err != nil {
			return false, err
		}
		var rev int64
		if len(resp.Kvs) == 1 {
			next, err := strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
			if err != nil {
				return false, fmt.Errorf("corrupt network ID counter: %w", err)
			}
			if next > uint64(id) {
				return false, nil
			}
			rev = resp.Kvs[0].ModRevision
		}
		txn, err := s.cli.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", rev)).
			Then(clientv3.OpPut(key, want)).
			Commit()
		if err != nil {
			return false, err
		}
		if txn.Succeeded {
			return true, nil
		}
	}
	return false, errors.New("could not raise the network ID counter: too much contention")
}

// GetNetwork looks a network up by name or by numeric ID.
func (s *Store) GetNetwork(ctx context.Context, ref string) (Network, error) {
	name := ref
	if allDigits.MatchString(ref) {
		id, err := strconv.ParseUint(ref, 10, 32)
		if err != nil {
			return Network{}, fmt.Errorf("network %s: %w", ref, ErrNotFound)
		}
		resp, err := s.cli.Get(ctx, s.netIDKey(uint32(id)))
		if err != nil {
			return Network{}, err
		}
		if len(resp.Kvs) == 0 {
			return Network{}, fmt.Errorf("network %s: %w", ref, ErrNotFound)
		}
		name = string(resp.Kvs[0].Value)
	}
	resp, err := s.cli.Get(ctx, s.netNameKey(name))
	if err != nil {
		return Network{}, err
	}
	if len(resp.Kvs) == 0 {
		return Network{}, fmt.Errorf("network %s: %w", ref, ErrNotFound)
	}
	var n Network
	if err := json.Unmarshal(resp.Kvs[0].Value, &n); err != nil || n.ID == 0 {
		return Network{}, fmt.Errorf("network %s: corrupt record", ref)
	}
	return n, nil
}

// ListNetworks returns every network.
func (s *Store) ListNetworks(ctx context.Context) ([]Network, error) {
	resp, err := s.cli.Get(ctx, s.netNamePrefix(), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	nets := make([]Network, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var n Network
		if json.Unmarshal(kv.Value, &n) == nil && n.ID != 0 {
			nets = append(nets, n)
		}
	}
	return nets, nil
}

// DeleteNetwork removes a network. Unless force is set it refuses while any
// host still has an endpoint in it.
func (s *Store) DeleteNetwork(ctx context.Context, ref string, force bool) error {
	n, err := s.GetNetwork(ctx, ref)
	if err != nil {
		return err
	}
	eps := s.endpointsPrefix(n.ID)
	if !force {
		resp, err := s.cli.Get(ctx, eps, clientv3.WithPrefix(), clientv3.WithCountOnly())
		if err != nil {
			return err
		}
		if resp.Count > 0 {
			return fmt.Errorf("network %s has %d attached endpoint(s): %w", n.Name, resp.Count, ErrInUse)
		}
	}
	_, err = s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.Value(s.netIDKey(n.ID)), "=", n.Name)).
		Then(
			clientv3.OpDelete(s.netNameKey(n.Name)),
			clientv3.OpDelete(s.netIDKey(n.ID)),
			clientv3.OpDelete(eps, clientv3.WithPrefix()),
		).
		Commit()
	return err
}

// ---- endpoints ----

// PutEndpoint publishes an endpoint under the given lease.
func (s *Store) PutEndpoint(ctx context.Context, ep Endpoint, lease int64) error {
	_, err := s.cli.Put(ctx, s.endpointKey(ep.NetworkID, ep.NodeID, ep.EpID),
		mustJSON(endpointRecord{Names: ep.Names, Network: ep.Network}),
		clientv3.WithLease(clientv3.LeaseID(lease)))
	return err
}

type endpointRecord struct {
	Names   []string        `json:"names"`
	Network NetworkIdentity `json:"network"`
}

// DeleteEndpoint withdraws an endpoint.
func (s *Store) DeleteEndpoint(ctx context.Context, network uint32, node, ep uint16) error {
	_, err := s.cli.Delete(ctx, s.endpointKey(network, node, ep))
	return err
}

// ListEndpoints returns a network's endpoints on every host.
func (s *Store) ListEndpoints(ctx context.Context, network uint32) ([]Endpoint, error) {
	kvs, _, err := s.list(ctx, s.endpointsPrefix(network))
	if err != nil {
		return nil, err
	}
	return s.decodeEndpoints(network, kvs), nil
}

// WatchEndpoints keeps the caller in step with one network's endpoints until
// ctx is done.
func (s *Store) WatchEndpoints(ctx context.Context, network uint32, reset func([]Endpoint), put, del func(Endpoint)) {
	s.watch(ctx, s.endpointsPrefix(network),
		func(kvs []*mvccpb.KeyValue) { reset(s.decodeEndpoints(network, kvs)) },
		func(ev *clientv3.Event) {
			ep, ok := s.decodeEndpoint(network, ev.Kv, ev.Type != clientv3.EventTypeDelete)
			if !ok {
				return
			}
			if ev.Type == clientv3.EventTypeDelete {
				del(ep)
			} else {
				put(ep)
			}
		})
}

func (s *Store) decodeEndpoints(network uint32, kvs []*mvccpb.KeyValue) []Endpoint {
	eps := make([]Endpoint, 0, len(kvs))
	for _, kv := range kvs {
		if ep, ok := s.decodeEndpoint(network, kv, true); ok {
			eps = append(eps, ep)
		}
	}
	return eps
}

func (s *Store) decodeEndpoint(network uint32, kv *mvccpb.KeyValue, withValue bool) (Endpoint, bool) {
	nodeStr, epStr, ok := strings.Cut(strings.TrimPrefix(string(kv.Key), s.endpointsPrefix(network)), "/")
	if !ok {
		return Endpoint{}, false
	}
	node, err1 := strconv.ParseUint(nodeStr, 10, 16)
	epID, err2 := strconv.ParseUint(epStr, 10, 16)
	if err1 != nil || err2 != nil || !s.layout.ValidNode(uint16(node)) || !s.layout.ValidEndpoint(uint16(epID)) {
		return Endpoint{}, false
	}
	ep := Endpoint{NetworkID: network, NodeID: uint16(node), EpID: uint16(epID)}
	if withValue {
		var v endpointRecord
		if json.Unmarshal(kv.Value, &v) != nil {
			return Endpoint{}, false
		}
		ep.Names, ep.Network = v.Names, v.Network
	}
	return ep, true
}

// ---- leases ----

// Lease grants a lease and keeps it alive until ctx is done. The returned
// channel is closed when the lease is lost, at which point everything
// published under it is gone or about to be.
func (s *Store) Lease(ctx context.Context, ttl time.Duration) (int64, <-chan struct{}, error) {
	grant, err := s.cli.Grant(ctx, int64(ttl/time.Second))
	if err != nil {
		return 0, nil, err
	}
	ka, err := s.cli.KeepAlive(ctx, grant.ID)
	if err != nil {
		return 0, nil, err
	}
	lost := make(chan struct{})
	go func() {
		defer close(lost)
		for range ka {
		}
	}()
	return int64(grant.ID), lost, nil
}

// Revoke gives a lease up, removing everything published under it at once.
func (s *Store) Revoke(ctx context.Context, lease int64) error {
	_, err := s.cli.Revoke(ctx, clientv3.LeaseID(lease))
	return err
}

// ---- watching ----

// watch delivers the contents of prefix and then every change to it. After
// any interruption, including history having been compacted away, it starts
// over with reset, so the caller never has to reason about gaps.
func (s *Store) watch(ctx context.Context, prefix string, reset func([]*mvccpb.KeyValue), apply func(*clientv3.Event)) {
	backoff := time.Second
	for ctx.Err() == nil {
		kvs, rev, err := s.list(ctx, prefix)
		if err == nil {
			backoff = time.Second
			reset(kvs)
			wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
			for wr := range s.cli.Watch(wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(rev+1)) {
				if wr.Err() != nil {
					break
				}
				for _, ev := range wr.Events {
					apply(ev)
				}
			}
			cancel()
		}
		// Jitter, so that a thousand hosts do not all come back at once.
		select {
		case <-ctx.Done():
		case <-time.After(backoff/2 + rand.N(backoff)):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// listPage is how many keys list asks etcd for at a time. A node list of tens
// of thousands of hosts is several megabytes; pages keep each response small.
const listPage = 2000

// list returns everything under prefix as of one revision, and that revision.
func (s *Store) list(ctx context.Context, prefix string) ([]*mvccpb.KeyValue, int64, error) {
	var (
		kvs []*mvccpb.KeyValue
		rev int64
		key = prefix
		end = clientv3.GetPrefixRangeEnd(prefix)
	)
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(listPage)}
		if rev != 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.cli.Get(ctx, key, opts...)
		if err != nil {
			return nil, 0, err
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		kvs = append(kvs, resp.Kvs...)
		if !resp.More || len(resp.Kvs) == 0 {
			return kvs, rev, nil
		}
		key = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
