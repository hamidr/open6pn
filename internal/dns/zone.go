// Package dns is the per-host resolver for containers on private networks.
package dns

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Record identifies an endpoint within a network. Its addresses follow from
// the address layout, so nothing else needs storing.
type Record struct {
	Node uint16
	Ep   uint16
}

// Zone holds the names of every network this host takes part in. Each network
// is a separate namespace: a lookup names the network it is made from and can
// only ever see that network's records.
type Zone struct {
	mu   sync.RWMutex
	nets map[uint32]*network
}

type network struct {
	names map[string]map[Record]struct{}
	eps   map[Record][]string
}

// NewZone returns an empty zone.
func NewZone() *Zone {
	return &Zone{nets: make(map[uint32]*network)}
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// NormalizeName lower-cases a DNS name for an endpoint and checks it. Names
// may have several labels ("web.ams").
func NormalizeName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if len(n) > 200 || !nameRE.MatchString(n) {
		return "", fmt.Errorf("invalid DNS name %q", name)
	}
	return n, nil
}

// Set adds an endpoint or replaces its names.
func (z *Zone) Set(net uint32, r Record, names []string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := z.nets[net]
	if n == nil {
		n = &network{names: make(map[string]map[Record]struct{}), eps: make(map[Record][]string)}
		z.nets[net] = n
	}
	n.remove(r)
	n.eps[r] = names
	for _, name := range names {
		set := n.names[name]
		if set == nil {
			set = make(map[Record]struct{})
			n.names[name] = set
		}
		set[r] = struct{}{}
	}
}

// Delete removes an endpoint.
func (z *Zone) Delete(net uint32, r Record) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if n := z.nets[net]; n != nil {
		n.remove(r)
	}
}

// ReplaceRemote makes the records of every host other than self exactly eps.
// Records of self are left alone: they come from local state, not from etcd.
func (z *Zone) ReplaceRemote(net uint32, self uint16, eps map[Record][]string) {
	z.mu.Lock()
	var stale []Record
	if n := z.nets[net]; n != nil {
		for r := range n.eps {
			if _, ok := eps[r]; !ok && r.Node != self {
				stale = append(stale, r)
			}
		}
		for _, r := range stale {
			n.remove(r)
		}
	}
	z.mu.Unlock()
	for r, names := range eps {
		if r.Node != self {
			z.Set(net, r, names)
		}
	}
}

// Drop forgets a network entirely.
func (z *Zone) Drop(net uint32) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.nets, net)
}

// Lookup returns the endpoints called name in one network. The second result
// says whether the name exists at all.
func (z *Zone) Lookup(net uint32, name string) ([]Record, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	n := z.nets[net]
	if n == nil {
		return nil, false
	}
	set, ok := n.names[name]
	if !ok {
		return nil, false
	}
	out := make([]Record, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	return out, true
}

func (n *network) remove(r Record) {
	for _, name := range n.eps[r] {
		if set := n.names[name]; set != nil {
			delete(set, r)
			if len(set) == 0 {
				delete(n.names, name)
			}
		}
	}
	delete(n.eps, r)
}
