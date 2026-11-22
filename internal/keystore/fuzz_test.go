package keystore_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/forkcloser/taciturn/internal/keystore"
)

// Past the bound: a record file is bytes the agent reads on every request,
// and whoever can write the store can write any. Whatever the file holds,
// it is this key's valid record or the store is corrupt, never a panic and
// never another key's record; and what the store accepts it writes back
// and reads again as the same record.
func FuzzRecordFile(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","name":"bot"}`))

	// The store's own bytes for a record, as the seed the mutations start
	// from: the file a fuzzed input replaces is this record's.
	seedStore, err := keystore.Open(filepath.Join(f.TempDir(), "keys"))
	if err != nil {
		f.Fatal(err)
	}

	seedRecord, _ := key(f, "bot", 1)
	if err = seedStore.Create(seedRecord); err != nil {
		f.Fatal(err)
	}

	written, err := os.ReadFile(recordFile(seedStore, seedRecord))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(written)

	f.Fuzz(func(t *testing.T, data []byte) {
		store := open(t)
		record := seedRecord

		if err := os.WriteFile(recordFile(store, record), data, 0o600); err != nil {
			t.Fatal(err)
		}

		got, err := store.Get(record.Fingerprint)
		list, listErr := store.List()

		if err != nil {
			if !errors.Is(err, keystore.ErrCorrupt) {
				t.Fatalf("a record file the store does not take: %v", err)
			}

			if !errors.Is(listErr, keystore.ErrCorrupt) {
				t.Fatalf("Get refuses the file and List does not: %v", listErr)
			}

			return
		}

		// Taken: it is the record of the key the file is named after.
		if got.Fingerprint != record.Fingerprint || listErr != nil || len(list) != 1 || !sameRecord(list[0], got) {
			t.Fatalf("Get took %+v; List: %+v, %v", got, list, listErr)
		}

		// And the store writes it back as it read it.
		if err = store.Delete(got.Fingerprint); err != nil {
			t.Fatalf("deleting a record the store read: %v", err)
		}

		if err = store.Create(got); err != nil {
			t.Fatalf("writing back a record the store read: %v", err)
		}

		again, err := store.Get(got.Fingerprint)
		if err != nil || !sameRecord(again, got) {
			t.Fatalf("written back: %+v, %v; read first: %+v", again, err, got)
		}
	})
}
