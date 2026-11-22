//go:build linux

package datapath

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tcPriority = 1
	tcHandle   = 1
)

func bpfFilter(link netlink.Link, parent uint32, prog *ebpf.Program, name string) *netlink.BpfFilter {
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    tcHandle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  tcPriority,
		},
		Name:         name,
		DirectAction: true,
	}
	if prog != nil {
		f.Fd = prog.FD()
	}
	return f
}

// attachTC installs ingress and egress programs on link, replacing any
// earlier ones in place so no packet sees the interface without a program.
func attachTC(link netlink.Link, ingress, egress *ebpf.Program) error {
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("clsact qdisc: %w", err)
	}
	if err := netlink.FilterReplace(bpfFilter(link, netlink.HANDLE_MIN_INGRESS, ingress, "o6pn_ingress")); err != nil {
		return fmt.Errorf("ingress filter: %w", err)
	}
	if err := netlink.FilterReplace(bpfFilter(link, netlink.HANDLE_MIN_EGRESS, egress, "o6pn_egress")); err != nil {
		return fmt.Errorf("egress filter: %w", err)
	}
	return nil
}

func detachTC(link netlink.Link) {
	netlink.FilterDel(bpfFilter(link, netlink.HANDLE_MIN_INGRESS, nil, "o6pn_ingress"))
	netlink.FilterDel(bpfFilter(link, netlink.HANDLE_MIN_EGRESS, nil, "o6pn_egress"))
}

// WatchLinkDeletes calls fn with the ifindex of every interface that
// disappears, until ctx is done. The kernel drops notifications when the
// socket's buffer overflows; the subscription is then started again and
// resync is called, because deletions may have been missed.
func WatchLinkDeletes(ctx context.Context, fn func(ifindex int), resync func()) error {
	subscribe := func() (chan netlink.LinkUpdate, chan struct{}, error) {
		updates := make(chan netlink.LinkUpdate, 1024)
		done := make(chan struct{})
		err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
			ErrorCallback: func(error) {},
		})
		return updates, done, err
	}
	updates, done, err := subscribe()
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			case u, ok := <-updates:
				if ok {
					if u.Header.Type == unix.RTM_DELLINK {
						fn(int(u.Index))
					}
					continue
				}
			}
			// The subscription ended. Start another, however long it takes.
			close(done)
			for {
				if updates, done, err = subscribe(); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			resync()
		}
	}()
	return nil
}
