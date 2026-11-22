// Package api is the daemon's local control API: JSON over HTTP on a Unix
// socket. The CLI is its only client, but anything on the host that can open
// the socket can use it.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DefaultSocket is where the daemon listens.
const DefaultSocket = "/run/open6pn.sock"

// Node is a host in the mesh.
type Node struct {
	ID        uint16 `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Self      bool   `json:"self,omitempty"`
}

// Network is a private network.
type Network struct {
	ID        uint32    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// AttachRequest asks the daemon to put a container interface on a network.
//
// Give Netns alone and the daemon creates the veth pair. Give HostIf to use a
// pair that already exists, with either Netns (the daemon configures the
// container end) or ContainerMAC (the caller does, from the response).
type AttachRequest struct {
	Network      string   `json:"network"`
	Names        []string `json:"names,omitempty"`
	Netns        string   `json:"netns,omitempty"`
	HostIf       string   `json:"host_if,omitempty"`
	ContainerIf  string   `json:"container_if,omitempty"`
	ContainerMAC string   `json:"container_mac,omitempty"`
}

// Route is a route to configure inside the container.
type Route struct {
	Dst string `json:"dst"`
	Via string `json:"via"`
}

// DNSConfig is what goes in the container's resolv.conf.
type DNSConfig struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
}

// Endpoint is an attached container interface. Everything needed to
// configure the container end by hand is included.
type Endpoint struct {
	ID         string     `json:"id"`
	Network    string     `json:"network"`
	NetworkID  uint32     `json:"network_id"`
	NodeID     uint16     `json:"node_id"`
	EndpointID uint16     `json:"endpoint_id"`
	IPv6       string     `json:"ipv6"`
	IPv4       string     `json:"ipv4"`
	Names      []string   `json:"names,omitempty"`
	HostIf     string     `json:"host_if,omitempty"`
	MTU        int        `json:"mtu,omitempty"`
	Routes     []Route    `json:"routes,omitempty"`
	DNS        *DNSConfig `json:"dns,omitempty"`
	AttachedAt time.Time  `json:"attached_at,omitempty"`
}

// Status describes the daemon on this host.
type Status struct {
	Node      Node              `json:"node"`
	Layout    Layout            `json:"layout"`
	Peers     int               `json:"peers"`
	Endpoints int               `json:"endpoints"`
	Networks  int               `json:"networks"`
	Stats     map[string]uint64 `json:"stats"`
}

// Layout is the cluster's address layout and the limits that follow from it.
type Layout struct {
	NodeBits     int `json:"node_bits"`
	MaxNodes     int `json:"max_nodes"`
	MaxEndpoints int `json:"max_endpoints_per_network_per_node"`
}

// Error is the body of a failed request.
type Error struct {
	Message string `json:"error"`
}

// Client talks to the daemon.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the daemon listening on socket.
func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 30 * time.Second,
	}}
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://open6pn"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the open6pn daemon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e Error
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Message != "" {
			return errors.New(e.Message)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Status() (s Status, err error) { return s, c.do("GET", "/v1/status", nil, &s) }
func (c *Client) Nodes() (n []Node, err error)  { return n, c.do("GET", "/v1/nodes", nil, &n) }
func (c *Client) RemoveNode(id uint16) error {
	return c.do("DELETE", fmt.Sprintf("/v1/nodes/%d", id), nil, nil)
}

func (c *Client) Networks() (n []Network, err error) { return n, c.do("GET", "/v1/networks", nil, &n) }
func (c *Client) CreateNetwork(name string) (n Network, err error) {
	return n, c.do("POST", "/v1/networks", Network{Name: name}, &n)
}
func (c *Client) RemoveNetwork(ref string, force bool) error {
	path := "/v1/networks/" + url.PathEscape(ref)
	if force {
		path += "?force=1"
	}
	return c.do("DELETE", path, nil, nil)
}

// NetworkEndpoints lists a network's endpoints on every host.
func (c *Client) NetworkEndpoints(ref string) (e []Endpoint, err error) {
	return e, c.do("GET", "/v1/networks/"+url.PathEscape(ref)+"/endpoints", nil, &e)
}

// Endpoints lists the endpoints attached on this host.
func (c *Client) Endpoints() (e []Endpoint, err error) {
	return e, c.do("GET", "/v1/endpoints", nil, &e)
}
func (c *Client) Attach(req AttachRequest) (e Endpoint, err error) {
	return e, c.do("POST", "/v1/endpoints", req, &e)
}

// Detach removes an endpoint, named by its ID or its host interface.
func (c *Client) Detach(ref string) error {
	return c.do("DELETE", "/v1/endpoints/"+url.PathEscape(ref), nil, nil)
}
