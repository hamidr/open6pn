//go:build linux

package datapath

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"open6pn/internal/addr"
)

// VethRequest describes the interface to prepare for an endpoint.
//
// Three shapes are accepted:
//
//	Netns only            create a veth pair and put one end in the namespace
//	HostIf + Netns        use an existing pair; configure its end in the namespace
//	HostIf + ContainerMAC use an existing pair; leave the container end to the caller
type VethRequest struct {
	HostIf       string
	Netns        string // path, e.g. /proc/<pid>/ns/net
	ContainerIf  string // name for a created interface inside the namespace
	ContainerMAC net.HardwareAddr
	V6, V4       netip.Addr
	MTU          int
}

// Veth is a prepared interface. Its host side is still down: AttachEndpoint
// brings it up once the programs are in place.
type Veth struct {
	HostIf       string
	Ifindex      int
	HostMAC      net.HardwareAddr
	ContainerMAC net.HardwareAddr
	Created      bool
}

// SetupVeth prepares the host side of an endpoint's veth and, when it is
// given the namespace, the container side as well.
func SetupVeth(req VethRequest) (v Veth, err error) {
	var ns netns.NsHandle = -1
	if req.Netns != "" {
		ns, err = netns.GetFromPath(req.Netns)
		if err != nil {
			return v, fmt.Errorf("open namespace %s: %w", req.Netns, err)
		}
		defer ns.Close()
	}

	var host netlink.Link
	switch {
	case req.HostIf == "" && req.Netns == "":
		return v, errors.New("either a host veth or a network namespace is required")
	case req.HostIf == "":
		host, err = createVeth(ns, req)
		if err != nil {
			return v, err
		}
		v.Created = true
		defer func() {
			if err != nil {
				netlink.LinkDel(host)
			}
		}()
	default:
		host, err = netlink.LinkByName(req.HostIf)
		if err != nil {
			return v, fmt.Errorf("host interface %s: %w", req.HostIf, err)
		}
		if host.Type() != "veth" {
			return v, fmt.Errorf("%s is a %s device, not a veth", req.HostIf, host.Type())
		}
		// It may be up already. Until the programs are attached it must
		// not carry anything: what the container sent would land in the
		// host's IP stack. AttachEndpoint brings it up again.
		if err = netlink.LinkSetDown(host); err != nil {
			return v, fmt.Errorf("set %s down: %w", req.HostIf, err)
		}
	}
	v.HostIf = host.Attrs().Name
	v.Ifindex = host.Attrs().Index
	v.HostMAC = host.Attrs().HardwareAddr

	if req.Netns != "" {
		v.ContainerMAC, err = configureContainerSide(ns, host, req)
		if err != nil {
			return v, err
		}
	} else {
		if len(req.ContainerMAC) != 6 {
			return v, errors.New("without a network namespace, the container interface's MAC address is required")
		}
		v.ContainerMAC = req.ContainerMAC
	}

	// The rest of the host side is AttachEndpoint's to do.
	if host.Attrs().MTU != req.MTU {
		if err = netlink.LinkSetMTU(host, req.MTU); err != nil {
			return v, fmt.Errorf("set MTU on %s: %w", v.HostIf, err)
		}
	}
	return v, nil
}

// gatewayAddr is the address on the host side of every veth.
func gatewayAddr() *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{IP: addr.Gateway6.AsSlice(), Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
		Scope: int(netlink.SCOPE_LINK),
	}
}

// DeleteVeth removes a veth pair this package created.
func DeleteVeth(ifindex int, name string) {
	if link, err := netlink.LinkByIndex(ifindex); err == nil && link.Attrs().Name == name {
		netlink.LinkDel(link)
	}
}

func createVeth(ns netns.NsHandle, req VethRequest) (netlink.Link, error) {
	suffix := make([]byte, 5)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	hostName := "o6pn" + hex.EncodeToString(suffix) // 14 characters; the limit is 15
	peerName := "mtmp" + hex.EncodeToString(suffix)

	la := netlink.NewLinkAttrs()
	la.Name = hostName
	la.MTU = req.MTU
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: peerName, PeerNamespace: netlink.NsFd(int(ns))}); err != nil {
		return nil, fmt.Errorf("create veth: %w", err)
	}
	host, err := netlink.LinkByName(hostName)
	if err != nil {
		return nil, err
	}

	name := req.ContainerIf
	if name == "" {
		name = "o6pn0"
	}
	nh, err := netlink.NewHandleAt(ns)
	if err != nil {
		netlink.LinkDel(host)
		return nil, err
	}
	defer nh.Close()
	peer, err := nh.LinkByName(peerName)
	if err == nil {
		err = nh.LinkSetName(peer, name)
	}
	if err != nil {
		netlink.LinkDel(host)
		return nil, fmt.Errorf("name container interface %s: %w", name, err)
	}
	return host, nil
}

// configureContainerSide sets addresses and routes on the peer of host inside
// the namespace and returns the peer's MAC address.
func configureContainerSide(ns netns.NsHandle, host netlink.Link, req VethRequest) (net.HardwareAddr, error) {
	nh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, err
	}
	defer nh.Close()

	peer, err := nh.LinkByIndex(host.Attrs().ParentIndex)
	if err != nil || peer.Type() != "veth" || peer.Attrs().ParentIndex != host.Attrs().Index {
		return nil, fmt.Errorf("the peer of %s is not in namespace %s", host.Attrs().Name, req.Netns)
	}
	name := peer.Attrs().Name
	idx := peer.Attrs().Index

	// A namespace may have IPv6 switched off for new interfaces.
	inNetns(ns, func() error {
		return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("0"), 0o644)
	})

	if err := nh.LinkSetMTU(peer, req.MTU); err != nil {
		return nil, fmt.Errorf("container %s: set MTU: %w", name, err)
	}
	if err := nh.AddrReplace(peer, &netlink.Addr{IPNet: hostNet(req.V6), Flags: unix.IFA_F_NODAD}); err != nil {
		return nil, fmt.Errorf("container %s: assign %s: %w", name, req.V6, err)
	}
	if err := nh.AddrReplace(peer, &netlink.Addr{IPNet: hostNet(req.V4)}); err != nil {
		return nil, fmt.Errorf("container %s: assign %s: %w", name, req.V4, err)
	}
	if err := nh.LinkSetUp(peer); err != nil {
		return nil, fmt.Errorf("container %s: set up: %w", name, err)
	}

	routes := []*netlink.Route{
		{LinkIndex: idx, Dst: prefixNet(addr.Cluster6), Gw: addr.Gateway6.AsSlice()},
		{LinkIndex: idx, Dst: hostNet(addr.Gateway4), Scope: netlink.SCOPE_LINK},
		{LinkIndex: idx, Dst: prefixNet(addr.Cluster4), Gw: addr.Gateway4.AsSlice(), Flags: int(netlink.FLAG_ONLINK)},
	}
	for _, r := range routes {
		if err := nh.RouteReplace(r); err != nil {
			return nil, fmt.Errorf("container %s: route %s: %w", name, r.Dst, err)
		}
	}
	return peer.Attrs().HardwareAddr, nil
}

// inNetns runs fn on a thread that has entered ns. If the thread cannot be
// returned to its original namespace it is left locked, which makes the Go
// runtime discard it.
func inNetns(ns netns.NsHandle, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer orig.Close()
		if err := netns.Set(ns); err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		err = fn()
		if netns.Set(orig) == nil {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}
