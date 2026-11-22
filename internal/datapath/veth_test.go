//go:build linux

package datapath

import "testing"

func TestHostMACIsLocallyAdministeredUnicast(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		mac, err := newHostMAC()
		if err != nil {
			t.Fatal(err)
		}
		if len(mac) != 6 {
			t.Fatalf("%s: want 6 bytes, got %d", mac, len(mac))
		}
		if mac[0]&0x01 != 0 {
			t.Fatalf("%s is a multicast address", mac)
		}
		if mac[0]&0x02 == 0 {
			t.Fatalf("%s is not locally administered", mac)
		}
		seen[mac.String()] = true
	}
	if len(seen) < 990 {
		t.Fatalf("only %d distinct addresses in 1000", len(seen))
	}
}
