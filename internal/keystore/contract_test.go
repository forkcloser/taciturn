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
	"slices"
	"strconv"
	"strings"
	"sync"
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

	// A refusal made while the lock is held is the store's, not the lock's.
	err := store.Create(other)
	if err == nil || !errors.Is(err, keystore.ErrExists) || strings.Contains(err.Error(), "lock") {
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

func TestEdit(t *testing.T) {
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
	want := record
	want.Name = "bot@2026"
	want.Retired = &retired
	want.Successor = other.Fingerprint
	want.Policy.Namespaces = nil

	set := func(to keystore.Record) func(*keystore.Record) error {
		return func(r *keystore.Record) error {
			*r = to

			return nil
		}
	}

	// By name, then by fingerprint: the record written is the one returned
	// and the one read back.
	for _, step := range []struct{ handle, name string }{
		{"bot", "bot@2026"},
		{record.Fingerprint, "bot@2027"},
	} {
		want.Name = step.name

		edited, err := store.Edit(step.handle, set(want))
		if err != nil || !sameRecord(edited, want) {
			t.Fatalf("edit by %s: %+v %v", step.handle, edited, err)
		}

		got, err := store.Get(record.Fingerprint)
		if err != nil || !sameRecord(got, want) {
			t.Fatalf("after the edit by %s: %+v %v", step.handle, got, err)
		}
	}

	// Each refusal leaves the record as it was.
	renamed, swapped, unnamed := want, other, want
	renamed.Name = "other"
	unnamed.Name = ""
	refusal := errors.New("the change refuses")

	for name, c := range map[string]struct {
		handle string
		change func(*keystore.Record) error
		want   error
	}{
		"a name another key holds":   {record.Fingerprint, set(renamed), keystore.ErrExists},
		"another key's record":       {record.Fingerprint, set(swapped), keystore.ErrInvalid},
		"a record the store refuses": {record.Fingerprint, set(unnamed), keystore.ErrInvalid},
		"the change's own error":     {record.Fingerprint, func(*keystore.Record) error { return refusal }, refusal},
		"an absent name":             {"missing", set(want), keystore.ErrNotFound},
		"an absent fingerprint":      {"SHA256:" + strings.Repeat("A", 43), set(want), keystore.ErrNotFound},
		"a malformed name":           {"-bot", set(want), keystore.ErrInvalid},
		"a malformed fingerprint":    {"SHA256:short", set(want), keystore.ErrInvalid},
	} {
		if _, err := store.Edit(c.handle, c.change); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v", name, err)
		}

		got, err := store.Get(record.Fingerprint)
		if err != nil || !sameRecord(got, want) {
			t.Fatalf("after %s: %+v %v", name, got, err)
		}
	}
}

// Edits made at once all land: each adds its own namespace to the record
// it reads under the lock, and none overwrites another's.
func TestEditsAtOnceAllLand(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)
	record.Policy.Namespaces = nil

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	const editors = 16

	var group sync.WaitGroup

	for i := range editors {
		group.Go(func() {
			_, err := store.Edit("bot", func(r *keystore.Record) error {
				r.Policy.Namespaces = append(slices.Clone(r.Policy.Namespaces), strconv.Itoa(i))

				return nil
			})
			if err != nil {
				t.Errorf("edit %d: %v", i, err)
			}
		})
	}

	group.Wait()

	got, err := store.Get(record.Fingerprint)
	if err != nil || len(got.Policy.Namespaces) != editors {
		t.Fatalf("%d edits left %v, %v", editors, got.Policy.Namespaces, err)
	}
}

// A rotation hands the name over in one step: the key is renamed and linked
// to its successor, which takes the name, the key as its predecessor and the
// policy the key holds in the store by then, whatever the caller's copies
// say. What it refuses, it refuses whole.
func TestRotate(t *testing.T) {
	t.Parallel()

	store := open(t)
	record, _ := key(t, "bot", 1)
	bystander, _ := key(t, "taken", 2)

	for _, one := range []keystore.Record{record, bystander} {
		if err := store.Create(one); err != nil {
			t.Fatal(err)
		}
	}

	looked, err := store.Lookup("bot")
	if err != nil {
		t.Fatal(err)
	}

	// An edit made after the lookup, before the rotation.
	if _, err = store.Edit("bot", func(r *keystore.Record) error {
		r.Policy.Namespaces = []string{"git", "file"}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The successor as the caller made it: its own name and policy are not
	// what the store writes.
	successor, _ := key(t, "ignored", 3)
	successor.Policy = policy.Policy{}

	refusals := map[string]struct {
		looked    keystore.Record
		renamed   string
		successor keystore.Record
		want      error
	}{
		"a name another key holds": {looked, "taken", successor, keystore.ErrExists},
		"a name that is not one":   {looked, "no spaces", successor, keystore.ErrInvalid},
		"a successor in the store": {looked, "bot@1", bystander, keystore.ErrExists},
		"a successor that is no key": {
			looked,
			"bot@1",
			keystore.Record{Fingerprint: successor.Fingerprint},
			keystore.ErrInvalid,
		},
		"a key the store does not have": {successor, "bot@1", successor, keystore.ErrNotFound},
		"a key that is not one":         {keystore.Record{Fingerprint: "bot"}, "bot@1", successor, keystore.ErrInvalid},
	}

	for name, c := range refusals {
		if _, _, err = store.Rotate(c.looked, c.renamed, c.successor); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	if list, listErr := store.List(); listErr != nil || len(list) != 2 || list[0].Name != "bot" ||
		list[0].Successor != "" {
		t.Fatalf("the store after the refusals: %+v, %v", list, listErr)
	}

	old, next, err := store.Rotate(looked, "bot@1", successor)
	if err != nil {
		t.Fatal(err)
	}

	if old.Fingerprint != record.Fingerprint || old.Name != "bot@1" || old.Successor != successor.Fingerprint {
		t.Fatalf("the rotated key: %+v", old)
	}

	if next.Fingerprint != successor.Fingerprint || next.Name != "bot" || next.Predecessor != record.Fingerprint ||
		!slices.Equal(next.Policy.Namespaces, []string{"git", "file"}) || !samePolicy(next.Policy, old.Policy) {
		t.Fatalf("the successor: %+v", next)
	}

	for _, written := range []keystore.Record{old, next} {
		got, getErr := store.Get(written.Fingerprint)
		if getErr != nil || !sameRecord(got, written) {
			t.Fatalf("the store holds %+v, %v; Rotate returned %+v", got, getErr, written)
		}
	}

	// The lookup is stale now: the key was rotated since.
	another, _ := key(t, "another", 4)
	if _, _, err = store.Rotate(looked, "bot@2", another); !errors.Is(err, keystore.ErrExists) {
		t.Fatalf("a rotation from a lookup made before another rotation: %v", err)
	}

	// A retired key is not rotated.
	when := created.Add(time.Hour)

	retired, err := store.Edit("bot", func(r *keystore.Record) error {
		r.Retired = &when

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err = store.Rotate(retired, "bot@2", another); !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("a rotation of a retired key: %v", err)
	}

	if list, listErr := store.List(); listErr != nil || len(list) != 3 {
		t.Fatalf("the store at the end: %+v, %v", list, listErr)
	}
}

// Of the rotations of one key made at once, from stores opened apart as two
// commands open them, one hands the name over and the others are refused
// and write nothing: the key is linked to the one successor the store holds.
func TestRotationsAtOnce(t *testing.T) {
	t.Parallel()

	const rotations = 8

	first := open(t)
	record, _ := key(t, "bot", 1)

	if err := first.Create(record); err != nil {
		t.Fatal(err)
	}

	var (
		group sync.WaitGroup
		mu    sync.Mutex
		won   []string
	)

	// Each looks the key up before any has rotated it, from a store opened
	// apart.
	stores := make([]*keystore.Store, rotations)
	looked := make([]keystore.Record, rotations)

	for index := range rotations {
		store, err := keystore.Open(first.Dir())
		if err != nil {
			t.Fatal(err)
		}

		stores[index] = store

		if looked[index], err = store.Lookup("bot"); err != nil {
			t.Fatal(err)
		}
	}

	for index := range rotations {
		successor, _ := key(t, "bot", byte(10+index))

		group.Go(func() {
			_, next, rotateErr := stores[index].Rotate(looked[index], "bot@"+strconv.Itoa(index), successor)

			switch {
			case rotateErr == nil:
				mu.Lock()
				defer mu.Unlock()

				won = append(won, next.Fingerprint)
			case !errors.Is(rotateErr, keystore.ErrExists):
				t.Errorf("rotation %d: %v", index, rotateErr)
			}
		})
	}

	group.Wait()

	if len(won) != 1 {
		t.Fatalf("%d rotations handed the name over", len(won))
	}

	list, err := first.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("the store after the rotations: %+v, %v", list, err)
	}

	old, err := first.Get(record.Fingerprint)
	if err != nil || old.Successor != won[0] || !strings.HasPrefix(old.Name, "bot@") {
		t.Fatalf("the rotated key: %+v, %v", old, err)
	}

	next, err := first.Lookup("bot")
	if err != nil || next.Fingerprint != won[0] || next.Predecessor != record.Fingerprint {
		t.Fatalf("the successor: %+v, %v", next, err)
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

// A record file is read up to the bound, 64 KiB, and refused past it,
// before a byte of it is decoded.
func TestRecordFileBound(t *testing.T) {
	t.Parallel()

	const bound = 64 * 1024

	store := open(t)
	record, _ := key(t, "bot", 1)

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(recordFile(store, record))
	if err != nil {
		t.Fatal(err)
	}

	// JSON takes any amount of white space after the value.
	padded := slices.Concat(written, bytes.Repeat([]byte{' '}, bound-len(written)))
	if err = os.WriteFile(recordFile(store, record), padded, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(record.Fingerprint)
	if err != nil || !sameRecord(got, record) {
		t.Fatalf("a record file of exactly the bound: %v", err)
	}

	if err = os.WriteFile(recordFile(store, record), append(padded, ' '), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err = store.Get(record.Fingerprint); !errors.Is(err, keystore.ErrCorrupt) {
		t.Fatalf("a record file one byte over the bound: %v", err)
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

			// An edit reads the whole store first: it is refused before
			// the change is asked for anything.
			asked := false

			_, err := store.Edit("bot", func(*keystore.Record) error {
				asked = true

				return nil
			})
			if !errors.Is(err, keystore.ErrCorrupt) || asked {
				t.Fatalf("Edit beside corruption: %v, change asked: %v", err, asked)
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
