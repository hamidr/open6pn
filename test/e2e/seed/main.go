// Command seed registers placeholder hosts in etcd, so the end-to-end test can
// run three real hosts inside a mesh of thousands: every real host then
// carries that many WireGuard peers and gets a node ID above them.
//
// The placeholders have random public keys and addresses in 198.18.0.0/15
// (reserved for benchmarking). Nothing is ever sent to them: WireGuard only
// contacts a peer when there is traffic for it.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"open6pn/internal/store"
)

func main() {
	etcd := flag.String("etcd", "", "etcd endpoints, comma-separated")
	prefix := flag.String("etcd-prefix", "/open6pn", "key prefix")
	count := flag.Int("count", 0, "placeholder hosts to register, as node IDs 1..count")
	flag.Parse()

	cli, err := clientv3.New(clientv3.Config{Endpoints: strings.Split(*etcd, ","), DialTimeout: 5 * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
	defer cli.Close()

	const batch = 100 // etcd allows 128 operations per transaction
	ctx := context.Background()
	for first := 1; first <= *count; first += batch {
		var ops []clientv3.Op
		for id := first; id < first+batch && id <= *count; id++ {
			key := make([]byte, 32)
			rand.Read(key)
			n := store.Node{
				ID:        uint16(id),
				Name:      fmt.Sprintf("placeholder-%d", id),
				PublicKey: base64.StdEncoding.EncodeToString(key),
				Endpoint:  fmt.Sprintf("198.18.%d.%d:51820", id>>8, id&0xff),
			}
			v, _ := json.Marshal(n)
			ops = append(ops, clientv3.OpPut(fmt.Sprintf("%s/nodes/%05d", *prefix, id), string(v)))
		}
		if _, err := cli.Txn(ctx).Then(ops...).Commit(); err != nil {
			fmt.Fprintln(os.Stderr, "seed:", err)
			os.Exit(1)
		}
	}
}
