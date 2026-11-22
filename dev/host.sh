#!/bin/sh
# Entrypoint of a mesh host in the Compose dev setup (../compose.yaml).
#
# It does what a container runtime's integration would do on a real host:
#
#   1. runs the open6pn daemon, which joins the host to the mesh;
#   2. creates the networks named in OPEN6PN_NETWORKS, if they do not exist yet;
#   3. attaches every tenant container that belongs on this host.
#
# A tenant container shares this container's PID namespace (pid: service:nX),
# which makes its network namespace reachable as /proc/PID/ns/net. It says
# which network it wants with OPEN6PN_NETWORK, and optionally which DNS names
# with OPEN6PN_NAMES (comma-separated).
set -u

ETCD=${OPEN6PN_ETCD:-http://etcd:2379}
ADVERTISE=$(hostname -i | awk '{print $1}')
IFNAME=o6pn0
READY=/run/open6pn-dev-ready

rm -f "$READY"

trap 'kill "$supervisor" 2>/dev/null; pkill -TERM -x open6pn; exit 0' TERM INT

# Keep the daemon running. Killing it (pkill -x open6pn) is a way to try a daemon
# restart: traffic between attached containers continues meanwhile.
(
	trap - TERM INT
	while :; do
		# shellcheck disable=SC2086
		open6pn daemon --etcd "$ETCD" --advertise "$ADVERTISE" ${OPEN6PN_DAEMON_FLAGS:-}
		echo "dev: open6pn daemon exited ($?), starting it again"
		sleep 1
	done
) &
supervisor=$!

until open6pn status >/dev/null 2>&1; do sleep 0.2; done

for net in $(echo "${OPEN6PN_NETWORKS:-}" | tr ',' ' '); do
	if ! open6pn network ls --json | jq -e --arg n "$net" 'any(.[]?; .name == $n)' >/dev/null; then
		open6pn network create "$net" | sed 's/^/dev: created network /'
	fi
done
touch "$READY"

env_of() { tr '\0' '\n' <"$1/environ" 2>/dev/null | sed -n "s/^$2=//p" | head -n1; }

self=$(readlink /proc/self/ns/net)
complained=""
while :; do
	for proc in /proc/[0-9]*; do
		net=$(env_of "$proc" OPEN6PN_NETWORK)
		[ -n "$net" ] || continue
		ns=$(readlink "$proc/ns/net" 2>/dev/null) || continue
		[ "$ns" != "$self" ] || continue
		# Every process of a container has the same namespace; attach it once.
		nsenter --net="$proc/ns/net" ip link show "$IFNAME" >/dev/null 2>&1 && continue

		flags=""
		for name in $(env_of "$proc" OPEN6PN_NAMES | tr ',' ' '); do flags="$flags --name $name"; done
		who=$(cat "$proc/root/etc/hostname" 2>/dev/null || echo "pid ${proc#/proc/}")
		# shellcheck disable=SC2086
		if out=$(open6pn attach --netns "$proc/ns/net" --ifname "$IFNAME" $flags "$net" 2>&1); then
			echo "dev: attached $who to $net: $(echo "$out" | jq -r '[.ipv6, .ipv4, (.names | join(","))] | join("  ")')"
		else
			case " $complained " in
			*" $ns "*) ;;
			*) echo "dev: attaching $who to $net failed, will keep trying: $out"; complained="$complained $ns" ;;
			esac
		fi
	done
	sleep 1
done
