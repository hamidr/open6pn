// Package state is the daemon's local record of what it owns on this host:
// its identity and the endpoints it has attached. These files are the source
// of truth for local endpoints; etcd only holds what other hosts need to see.
//
// The directory holds:
//
//	state.json            the node's identity and a few host-wide facts
//	endpoints/<id>.json   one file per attached endpoint
//
// One file per endpoint keeps attaching and detaching cheap on a host with
// tens of thousands of endpoints: only that endpoint's file is written.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Node is this host's identity in the mesh.
type Node struct {
	ID         uint16 `json:"id"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

// Endpoint is one attached container interface.
type Endpoint struct {
	ID          string `json:"id"`
	NetworkID   uint32 `json:"network_id"`
	NetworkName string `json:"network_name"`
	// NetworkCreated tells two networks apart that were given the same ID,
	// which can only happen if etcd lost its history.
	NetworkCreated time.Time `json:"network_created,omitzero"`
	EpID           uint16    `json:"endpoint_id"`
	Names          []string  `json:"names,omitempty"`
	HostIf         string    `json:"host_if"`
	Ifindex        int       `json:"ifindex"`
	HostMAC        string    `json:"host_mac"`
	ContainerMAC   string    `json:"container_mac"`
	Created        bool      `json:"created"` // the daemon created the veth and deletes it on detach
	AttachedAt     time.Time `json:"attached_at"`
}

// State is the content of state.json.
type State struct {
	Node *Node `json:"node,omitempty"`
	// NodeBits is the cluster's address layout as this host last saw it.
	// Every endpoint address depends on it.
	NodeBits int `json:"node_bits,omitempty"`
	// BootID is the kernel boot the endpoints were attached in. After a
	// reboot none of their interfaces can still exist, whatever an
	// interface index or name seems to say.
	BootID string `json:"boot_id,omitempty"`
	// Cursors is the next endpoint ID to try in each network, so that an
	// address is not handed out again the moment it becomes free.
	Cursors map[uint32]uint16 `json:"cursors,omitempty"`

	// Legacy is where endpoints were kept before each had its own file.
	// Load moves them out; it is never written.
	Legacy []Endpoint `json:"endpoints,omitempty"`
}

// Dir is a state directory.
type Dir struct{ path string }

// Open returns the state directory at path, creating it if need be.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(filepath.Join(path, "endpoints"), 0o700); err != nil {
		return nil, err
	}
	return &Dir{path: path}, nil
}

// Path returns the file holding the node's identity.
func (d *Dir) Path() string { return filepath.Join(d.path, "state.json") }

// Load reads state.json. A missing file is an empty state.
//
// A state.json written before endpoints had files of their own still lists
// them. They are given their files first and only then dropped from
// state.json, so an interruption at any point loses nothing.
func (d *Dir) Load() (*State, error) {
	var s State
	if err := readJSON(d.Path(), &s); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(s.Legacy) > 0 {
		for i := range s.Legacy {
			if err := d.SaveEndpoint(&s.Legacy[i]); err != nil {
				return nil, fmt.Errorf("move endpoint %s to its own file: %w", s.Legacy[i].ID, err)
			}
		}
		s.Legacy = nil
		if err := d.Save(&s); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// Save replaces state.json. It holds the WireGuard private key, so it is only
// readable by its owner.
func (d *Dir) Save(s *State) error { return writeJSON(d.Path(), s) }

var endpointID = regexp.MustCompile(`^[0-9a-f]{1,32}$`)

func (d *Dir) endpointPath(id string) (string, error) {
	if !endpointID.MatchString(id) {
		return "", fmt.Errorf("invalid endpoint ID %q", id)
	}
	return filepath.Join(d.path, "endpoints", id+".json"), nil
}

// Endpoints reads every endpoint file. Files that cannot be read are reported
// in bad and skipped: one damaged file must not cost the host its other
// endpoints.
func (d *Dir) Endpoints() (eps []Endpoint, bad []error, err error) {
	entries, err := os.ReadDir(filepath.Join(d.path, "endpoints"))
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !endpointID.MatchString(id) {
			continue // a temporary file from an interrupted write
		}
		var ep Endpoint
		if err := readJSON(filepath.Join(d.path, "endpoints", e.Name()), &ep); err != nil {
			bad = append(bad, err)
			continue
		}
		if ep.ID != id {
			bad = append(bad, fmt.Errorf("%s holds endpoint %q", e.Name(), ep.ID))
			continue
		}
		eps = append(eps, ep)
	}
	return eps, bad, nil
}

// SaveEndpoint writes one endpoint's file.
func (d *Dir) SaveEndpoint(ep *Endpoint) error {
	path, err := d.endpointPath(ep.ID)
	if err != nil {
		return err
	}
	return writeJSON(path, ep)
}

// DeleteEndpoint removes one endpoint's file. It is not an error for the file
// to be gone already.
func (d *Dir) DeleteEndpoint(id string) error {
	path, err := d.endpointPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// writeJSON replaces path atomically, readable by its owner only.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
