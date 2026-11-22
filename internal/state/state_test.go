package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEndpointFiles(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"aa11", "bb22"} {
		if err := d.SaveEndpoint(&Endpoint{ID: id, NetworkID: 7, EpID: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// Left behind by an interrupted write, and something that is not ours.
	os.WriteFile(filepath.Join(d.path, "endpoints", ".tmp-123"), []byte("{"), 0o600)
	os.WriteFile(filepath.Join(d.path, "endpoints", "cc33.json"), []byte("not json"), 0o600)

	eps, bad, err := d.Endpoints()
	if err != nil || len(eps) != 2 || len(bad) != 1 {
		t.Fatalf("got %d endpoints, %d bad, err %v; want 2, 1, nil", len(eps), len(bad), err)
	}
	if err := d.DeleteEndpoint("aa11"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteEndpoint("aa11"); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	if eps, _, _ := d.Endpoints(); len(eps) != 1 || eps[0].ID != "bb22" {
		t.Errorf("after delete: %+v", eps)
	}
	if err := d.SaveEndpoint(&Endpoint{ID: "../escape"}); err == nil {
		t.Error("an ID that is not hex must be refused")
	}
}

// A state.json from before endpoints had their own files must not lose them.
func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	old := `{"node":{"id":3,"name":"h","private_key":"k"},"node_bits":14,
		"endpoints":[{"id":"aa11","network_id":7,"endpoint_id":1,"host_if":"o6pnaa"},
		             {"id":"bb22","network_id":8,"endpoint_id":2,"host_if":"o6pnbb"}]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.Load()
	if err != nil || s.Node == nil || s.Node.ID != 3 || len(s.Legacy) != 0 {
		t.Fatalf("load: %+v, %v", s, err)
	}
	eps, bad, err := d.Endpoints()
	if err != nil || len(bad) != 0 || len(eps) != 2 {
		t.Fatalf("got %d endpoints, %d bad, err %v; want 2, 0, nil", len(eps), len(bad), err)
	}
	// And it is done once: the list is gone from state.json.
	again, err := d.Load()
	if err != nil || len(again.Legacy) != 0 || again.Node.ID != 3 {
		t.Fatalf("second load: %+v, %v", again, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	var raw map[string]any
	if json.Unmarshal(b, &raw); raw["endpoints"] != nil {
		t.Errorf("state.json still lists endpoints: %s", b)
	}
}
