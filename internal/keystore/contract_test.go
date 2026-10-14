// The contract of package keystore is its package comment: one private
// record file per key under a private directory, replaced atomically,
// every read checked, the v0.1 blob read for the import alone, and the
// sentinels for what is refused. The tests here state each clause on one
// case; bounded_test.go walks the name and fingerprint validators to their
// edges and holds the store to a model over every short sequence of
// operations.
package keystore_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

var created = time.Date(2026, time.October, 12, 15, 0, 0, 0, time.UTC)

// key builds a record for a seed, and the blob a v0.1 store would hold for
// it: the seed decides the public key, so two seeds are two keys.
func key(t *testing.T, name string, seed byte) (keystore.Record, []byte) {
	t.Helper()

	point := append([]byte{4}, bytes.Repeat([]byte{seed}, 64)...)

	blob, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	record := keystore.Record{
		Fingerprint: protocol.Fingerprint(blob),
		Name:        name,
		PublicKey:   blob,
		Class:       keystore.ClassAfterFirstUnlock,
		Created:     created.Add(time.Duration(seed) * time.Minute),
		Policy: policy.Policy{
			Destinations: []policy.Destination{{User: "git", Host: "github.com", HostKeys: [][]byte{{1, 2, 3}}}},
			Namespaces:   []string{"git"},
			Peers:        []string{"path=/usr/bin/ssh"},
		},
	}

	return record, bytes.Repeat([]byte{0xE0 | seed}, 324)
}

func open(t *testing.T) *keystore.Store {
	t.Helper()

	store, err := keystore.Open(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}

	return store
}

// legacy puts a v0.1 blob file beside a record, as a store written before
// keys lived in the keychain holds it.
func legacy(t *testing.T, store *keystore.Store, record keystore.Record, blob []byte) {
	t.Helper()

	overwrite(t, blobFile(store, record), blob, 0o600)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	return info.Mode().Perm()
}

func TestOpenCreatesAPrivateDirectory(t *testing.T) {
	t.Parallel()

	store := open(t)

	if got := mode(t, store.Dir()); got != 0o700 {
		t.Fatalf("directory mode %o", got)
	}

	again, err := keystore.Open(store.Dir())
	if err != nil || again.Dir() != store.Dir() {
		t.Fatalf("reopen: %v", err)
	}
}

func TestOpenRefusesWhatIsNotPrivate(t *testing.T) {
	t.Parallel()

	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := keystore.Open(shared); !errors.Is(err, keystore.ErrInsecure) {
		t.Fatalf("group-readable directory: %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := keystore.Open(file); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("a file: %v", err)
	}
}

func TestCreateThenRead(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(record.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	if !sameRecord(got, record) {
		t.Fatalf("got %+v\nwant %+v", got, record)
	}

	byName, err := store.Lookup("bot")
	if err != nil || byName.Fingerprint != record.Fingerprint {
		t.Fatalf("lookup by name: %+v %v", byName, err)
	}

	byFingerprint, err := store.Lookup(record.Fingerprint)
	if err != nil || byFingerprint.Name != "bot" {
		t.Fatalf("lookup by fingerprint: %+v %v", byFingerprint, err)
	}

	if _, err = store.LegacyBlob(record.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("a new key has no legacy blob: %v", err)
	}

	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}

		if entry.Name() != fileID(record.Fingerprint)+".json" {
			t.Fatalf("unexpected file %s", entry.Name())
		}

		if got := mode(t, filepath.Join(store.Dir(), entry.Name())); got != 0o600 {
			t.Fatalf("%s has mode %o", entry.Name(), got)
		}
	}
}

func TestCreateRefusesDuplicates(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	if err := store.Create(record); !errors.Is(err, keystore.ErrExists) {
		t.Fatalf("same key again: %v", err)
	}

	other, _ := key(t, "bot", 2)
	if err := store.Create(other); !errors.Is(err, keystore.ErrExists) {
		t.Fatalf("same name, other key: %v", err)
	}

	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list after refusals: %d %v", len(list), err)
	}
}

func TestCreateRefusesBadInput(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)

	cases := map[string]func(*keystore.Record){
		"bad name":          func(r *keystore.Record) { r.Name = "no spaces" },
		"bad class":         func(r *keystore.Record) { r.Class = "always" },
		"no creation time":  func(r *keystore.Record) { r.Created = time.Time{} },
		"wrong fingerprint": func(r *keystore.Record) { r.Fingerprint = "SHA256:" + r.Fingerprint[8:] + "A" },
		"not a P-256 key":   func(r *keystore.Record) { r.PublicKey = []byte("ssh-ed25519") },
		"bad predecessor":   func(r *keystore.Record) { r.Predecessor = "bot" },
		"bad successor":     func(r *keystore.Record) { r.Successor = "SHA256:short" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := record
			mutate(&rec)

			if err := store.Create(rec); !errors.Is(err, keystore.ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}

	entries, _ := os.ReadDir(store.Dir())
	for _, e := range entries {
		if e.Name() != ".lock" {
			t.Fatalf("refused create left %s", e.Name())
		}
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)
	other, _ := key(t, "other", 2)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	if err := store.Create(other); err != nil {
		t.Fatal(err)
	}

	retired := created.Add(time.Hour)
	record.Name = "bot@2026"
	record.Retired = &retired
	record.Successor = other.Fingerprint
	record.Policy.Namespaces = nil

	if err := store.Update(record); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(record.Fingerprint)
	if err != nil || !sameRecord(got, record) {
		t.Fatalf("after update: %+v %v", got, err)
	}

	record.Name = "other"
	if err := store.Update(record); !errors.Is(err, keystore.ErrExists) {
		t.Fatalf("rename onto another key's name: %v", err)
	}

	missing, _ := key(t, "missing", 3)
	if err := store.Update(missing); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("update of an absent key: %v", err)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, blob := key(t, "bot", 1)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	legacy(t, store, record, blob)

	if err := store.Delete(record.Fingerprint); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Get(record.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}

	if _, err := os.Stat(blobFile(store, record)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the legacy blob outlived its record: %v", err)
	}

	if err := store.Delete(record.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}

	list, err := store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("list after delete: %d %v", len(list), err)
	}
}

// A v0.1 store's blob is read for the import, listed as pending until it is
// removed, and gone after; a record with no blob has none to give.
func TestLegacyBlob(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, blob := key(t, "bot", 1)
	fresh, _ := key(t, "fresh", 2)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	if err := store.Create(fresh); err != nil {
		t.Fatal(err)
	}

	legacy(t, store, record, blob)

	pending, err := store.LegacyBlobs()
	if err != nil || len(pending) != 1 || pending[0] != record.Fingerprint {
		t.Fatalf("pending: %v %v", pending, err)
	}

	got, err := store.LegacyBlob(record.Fingerprint)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("legacy blob: %x %v", got, err)
	}

	if _, err = store.LegacyBlob(fresh.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("blob of a key without one: %v", err)
	}

	if err = store.RemoveLegacyBlob(fresh.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("removing a blob a key does not have: %v", err)
	}

	if err = store.RemoveLegacyBlob(record.Fingerprint); err != nil {
		t.Fatal(err)
	}

	if _, err = store.LegacyBlob(record.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("blob after removal: %v", err)
	}

	pending, err = store.LegacyBlobs()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after removal: %v %v", pending, err)
	}

	legacy(t, store, record, make([]byte, keystore.MaxBlob+1))

	if _, err = store.LegacyBlob(record.Fingerprint); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("oversize blob: %v", err)
	}
}

func TestListIsOldestFirst(t *testing.T) {
	t.Parallel()

	store := open(t)

	for _, seed := range []byte{3, 1, 2} {
		record, _ := key(t, "k"+string(rune('0'+seed)), seed)
		if err := store.Create(record); err != nil {
			t.Fatal(err)
		}
	}

	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 3 || list[0].Name != "k1" || list[1].Name != "k2" || list[2].Name != "k3" {
		t.Fatalf("%+v", list)
	}
}

func TestCorruptionIsReportedNotServed(t *testing.T) {
	t.Parallel()

	breakages := map[string]func(t *testing.T, store *keystore.Store, record keystore.Record){
		"garbage record": func(t *testing.T, store *keystore.Store, record keystore.Record) {
			t.Helper()
			overwrite(t, recordFile(store, record), []byte("{not json"), 0o600)
		},
		"record of another key": func(t *testing.T, store *keystore.Store, record keystore.Record) {
			t.Helper()

			other, _ := key(t, "other", 9)
			data, _ := os.ReadFile(recordFile(store, record))
			data = bytes.ReplaceAll(data, []byte(record.Fingerprint), []byte(other.Fingerprint))
			overwrite(t, recordFile(store, record), data, 0o600)
		},
		"blob without record": func(t *testing.T, store *keystore.Store, record keystore.Record) {
			t.Helper()

			legacy(t, store, record, bytes.Repeat([]byte{1}, 324))

			if err := os.Remove(recordFile(store, record)); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, breakage := range breakages {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := open(t)
			record, _ := key(t, "bot", 1)

			if err := store.Create(record); err != nil {
				t.Fatal(err)
			}

			breakage(t, store, record)

			if _, err := store.List(); !errors.Is(err, keystore.ErrCorrupt) {
				t.Fatalf("List: %v", err)
			}

			if _, err := store.Lookup("bot"); !errors.Is(err, keystore.ErrCorrupt) {
				t.Fatalf("Lookup: %v", err)
			}

			other, _ := key(t, "other", 2)
			if err := store.Create(other); !errors.Is(err, keystore.ErrCorrupt) {
				t.Fatalf("Create beside corruption: %v", err)
			}
		})
	}
}

func TestAFileReadableByOthersIsInsecure(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, blob := key(t, "bot", 1)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	legacy(t, store, record, blob)

	if err := os.Chmod(blobFile(store, record), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := store.LegacyBlob(record.Fingerprint); !errors.Is(err, keystore.ErrInsecure) {
		t.Fatalf("group-readable blob: %v", err)
	}

	if err := os.Chmod(recordFile(store, record), 0o604); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Get(record.Fingerprint); !errors.Is(err, keystore.ErrInsecure) {
		t.Fatalf("world-readable record: %v", err)
	}
}

func TestLookupsValidateTheirArgument(t *testing.T) {
	t.Parallel()

	store := open(t)

	for _, bad := range []string{"", "SHA256:", "SHA256:tooshort", "-leading", "has space"} {
		if _, err := store.Lookup(bad); !errors.Is(err, keystore.ErrInvalid) {
			t.Fatalf("Lookup(%q): %v", bad, err)
		}
	}

	if _, err := store.Get("bot"); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("Get by name: %v", err)
	}

	if err := store.Delete("bot"); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("Delete by name: %v", err)
	}

	if _, err := store.LegacyBlob("bot"); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("LegacyBlob by name: %v", err)
	}

	record, _ := key(t, "bot", 1)
	if _, err := store.Lookup(record.Fingerprint); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("Lookup of an absent fingerprint: %v", err)
	}
}

func recordFile(store *keystore.Store, record keystore.Record) string {
	return filepath.Join(store.Dir(), fileID(record.Fingerprint)+".json")
}

func blobFile(store *keystore.Store, record keystore.Record) string {
	return filepath.Join(store.Dir(), fileID(record.Fingerprint)+".blob")
}

// fileID mirrors the package's file naming: the fingerprint's digest in the
// URL-safe alphabet. Stated here independently so a change there is seen.
func fileID(fingerprint string) string {
	digest := fingerprint[len("SHA256:"):]
	out := make([]byte, len(digest))

	for i := range len(digest) {
		switch digest[i] {
		case '/':
			out[i] = '_'
		case '+':
			out[i] = '-'
		default:
			out[i] = digest[i]
		}
	}

	return string(out)
}

func overwrite(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
}

// sameRecord compares records field by field, times by Equal.
func sameRecord(a, b keystore.Record) bool {
	if a.Fingerprint != b.Fingerprint || a.Name != b.Name || !bytes.Equal(a.PublicKey, b.PublicKey) ||
		a.Class != b.Class {
		return false
	}

	if !a.Created.Equal(b.Created) || (a.Retired == nil) != (b.Retired == nil) ||
		(a.Retired != nil && !a.Retired.Equal(*b.Retired)) {
		return false
	}

	if a.Predecessor != b.Predecessor || a.Successor != b.Successor {
		return false
	}

	return samePolicy(a.Policy, b.Policy)
}

func samePolicy(a, b policy.Policy) bool {
	if len(a.Destinations) != len(b.Destinations) || len(a.Namespaces) != len(b.Namespaces) ||
		len(a.Peers) != len(b.Peers) {
		return false
	}

	for i := range a.Destinations {
		x, y := a.Destinations[i], b.Destinations[i]
		if x.User != y.User || x.Host != y.Host || len(x.HostKeys) != len(y.HostKeys) {
			return false
		}

		for j := range x.HostKeys {
			if !bytes.Equal(x.HostKeys[j], y.HostKeys[j]) {
				return false
			}
		}
	}

	for i := range a.Namespaces {
		if a.Namespaces[i] != b.Namespaces[i] {
			return false
		}
	}

	for i := range a.Peers {
		if a.Peers[i] != b.Peers[i] {
			return false
		}
	}

	return true
}
