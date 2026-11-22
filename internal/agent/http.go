//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"open6pn/internal/addr"
	"open6pn/internal/api"
	"open6pn/internal/store"
)

type badRequestError struct{ error }

func badRequest(err error) error { return badRequestError{err} }

// serveAPI serves the control API on the Unix socket until ctx is done.
func (a *Agent) serveAPI(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.Socket), 0o755); err != nil {
		return err
	}
	// A socket file left by a previous run would make Listen fail.
	if _, err := net.DialTimeout("unix", a.cfg.Socket, time.Second); err == nil {
		return errors.New("another open6pn daemon is already serving " + a.cfg.Socket)
	}
	os.Remove(a.cfg.Socket)
	ln, err := net.Listen("unix", a.cfg.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(a.cfg.Socket, 0o600); err != nil {
		ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", a.handleStatus)
	mux.HandleFunc("GET /v1/nodes", a.handleNodes)
	mux.HandleFunc("DELETE /v1/nodes/{id}", a.handleRemoveNode)
	mux.HandleFunc("GET /v1/networks", a.handleNetworks)
	mux.HandleFunc("POST /v1/networks", a.handleCreateNetwork)
	mux.HandleFunc("DELETE /v1/networks/{ref}", a.handleRemoveNetwork)
	mux.HandleFunc("GET /v1/networks/{ref}/endpoints", a.handleNetworkEndpoints)
	mux.HandleFunc("GET /v1/endpoints", a.handleEndpoints)
	mux.HandleFunc("POST /v1/endpoints", a.handleAttach)
	mux.HandleFunc("DELETE /v1/endpoints/{ref}", a.handleDetach)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	a.log.Info("ready", "socket", a.cfg.Socket)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func fail(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	var bad badRequestError
	switch {
	case errors.As(err, &bad):
		code = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, store.ErrExists), errors.Is(err, store.ErrInUse):
		code = http.StatusConflict
	}
	reply(w, code, api.Error{Message: err.Error()})
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats, err := a.dp.Stats()
	if err != nil {
		fail(w, err)
		return
	}
	a.peersMu.Lock()
	peers := len(a.peers)
	a.peersMu.Unlock()
	a.mu.Lock()
	endpoints, networks := len(a.endpoints), len(a.watchers)
	a.mu.Unlock()
	reply(w, http.StatusOK, api.Status{
		Node:      api.Node{ID: a.node.ID, Name: a.node.Name, PublicKey: a.node.PublicKey, Endpoint: a.node.Endpoint, Self: true},
		Layout:    api.Layout{NodeBits: a.layout.NodeBits, MaxNodes: int(a.layout.MaxNode()), MaxEndpoints: int(a.layout.MaxEndpoint())},
		Peers:     peers,
		Endpoints: endpoints,
		Networks:  networks,
		Stats:     stats,
	})
}

func (a *Agent) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.store.ListNodes(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]api.Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, api.Node{ID: n.ID, Name: n.Name, PublicKey: n.PublicKey, Endpoint: n.Endpoint, Self: n.ID == a.node.ID})
	}
	reply(w, http.StatusOK, out)
}

func (a *Agent) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 16)
	if err != nil || !a.layout.ValidNode(uint16(id)) {
		fail(w, badRequest(errors.New("invalid node ID")))
		return
	}
	if err := a.store.DeleteNode(r.Context(), uint16(id)); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusNoContent, nil)
}

func (a *Agent) handleNetworks(w http.ResponseWriter, r *http.Request) {
	nets, err := a.store.ListNetworks(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]api.Network, 0, len(nets))
	for _, n := range nets {
		out = append(out, api.Network(n))
	}
	slices.SortFunc(out, func(x, y api.Network) int { return int(int64(x.ID) - int64(y.ID)) })
	reply(w, http.StatusOK, out)
}

func (a *Agent) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req api.Network
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, badRequest(err))
		return
	}
	if !store.ValidNetworkName(req.Name) {
		fail(w, badRequest(errors.New("invalid network name: use 1-63 of a-z, 0-9, '.', '_', '-', not only digits")))
		return
	}
	n, err := a.store.CreateNetwork(r.Context(), req.Name)
	if err != nil {
		fail(w, err)
		return
	}
	a.log.Info("network created", "name", n.Name, "id", n.ID)
	reply(w, http.StatusCreated, api.Network(n))
}

func (a *Agent) handleRemoveNetwork(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteNetwork(r.Context(), r.PathValue("ref"), r.URL.Query().Get("force") != ""); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusNoContent, nil)
}

func (a *Agent) handleNetworkEndpoints(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.GetNetwork(r.Context(), r.PathValue("ref"))
	if err != nil {
		fail(w, err)
		return
	}
	eps, err := a.store.ListEndpoints(r.Context(), n.ID)
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]api.Endpoint, 0, len(eps))
	for _, ep := range eps {
		out = append(out, api.Endpoint{
			Network:    n.Name,
			NetworkID:  n.ID,
			NodeID:     ep.NodeID,
			EndpointID: ep.EpID,
			IPv6:       addr.V6(ep.NodeID, n.ID, ep.EpID).String(),
			IPv4:       a.layout.V4(ep.NodeID, ep.EpID).String(),
			Names:      ep.Names,
		})
	}
	reply(w, http.StatusOK, out)
}

func (a *Agent) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	reply(w, http.StatusOK, a.Endpoints())
}

func (a *Agent) handleAttach(w http.ResponseWriter, r *http.Request) {
	var req api.AttachRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, badRequest(err))
		return
	}
	ep, err := a.Attach(r.Context(), req)
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusCreated, ep)
}

func (a *Agent) handleDetach(w http.ResponseWriter, r *http.Request) {
	if err := a.Detach(r.PathValue("ref")); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusNoContent, nil)
}
