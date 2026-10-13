package keystore_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/forkcloser/taciturn/internal/keystore"
)

// A name is 1 to MaxNameLength characters of the allowed set, not starting
// with '.' or '-': every length at the edges, every byte as a second
// character, and both forbidden first characters.
func TestNameBound(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, 1, keystore.MaxNameLength, keystore.MaxNameLength + 1} {
		err := keystore.ValidateName(strings.Repeat("a", length))

		valid := length >= 1 && length <= keystore.MaxNameLength
		if (err == nil) != valid {
			t.Fatalf("length %d: %v", length, err)
		}

		if !valid && !errors.Is(err, keystore.ErrInvalid) {
			t.Fatalf("length %d: %v", length, err)
		}
	}

	for c := range 256 {
		name := "a" + string(rune(c))

		allowed := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
			c == '@' ||
			c == '-'

		err := keystore.ValidateName(name)
		if (err == nil) != allowed {
			t.Fatalf("character %q: %v", rune(c), err)
		}
	}

	for _, first := range []string{".hidden", "-flag"} {
		if err := keystore.ValidateName(first); !errors.Is(err, keystore.ErrInvalid) {
			t.Fatalf("%q: %v", first, err)
		}
	}

	if err := keystore.ValidateName("a.b_c@d-e"); err != nil {
		t.Fatal(err)
	}
}

// A fingerprint is "SHA256:" and exactly 43 characters of the standard
// base64 alphabet, unpadded.
func TestFingerprintBound(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("A", 42) + "Q"

	cases := map[string]bool{
		"SHA256:" + digest:            true,
		"SHA256:" + digest[:42]:       false,
		"SHA256:" + digest + "A":      false,
		"SHA256:" + digest + "=":      false,
		"sha256:" + digest:            false,
		"MD5:" + digest:               false,
		digest:                        false,
		"SHA256:" + digest[:42] + "!": false,
		"SHA256:" + digest[:42] + "-": false,
		"SHA256:" + digest[:42] + "/": true,
		"SHA256:" + digest[:42] + "+": true,
		"":                            false,
	}

	for fingerprint, valid := range cases {
		err := keystore.ValidateFingerprint(fingerprint)
		if (err == nil) != valid {
			t.Fatalf("%q: %v", fingerprint, err)
		}

		if !valid && !errors.Is(err, keystore.ErrInvalid) {
			t.Fatalf("%q: %v", fingerprint, err)
		}
	}
}

// The store, held to a model: every sequence of up to four operations over
// two keys, the model being a map from fingerprint to record, with the
// outcome each operation must have given the map's state.
func TestEverySequenceAgainstTheModel(t *testing.T) {
	t.Parallel()

	var ops []op

	for _, kind := range []string{"create", "update", "delete"} {
		for _, k := range []int{0, 1} {
			ops = append(ops, op{kind, k})
		}
	}

	var walk func(t *testing.T, prefix []op)

	walk = func(t *testing.T, prefix []op) {
		t.Helper()

		if len(prefix) == 4 {
			return
		}

		for _, next := range ops {
			sequence := append(append([]op{}, prefix...), next)
			runSequence(t, sequence)
			walk(t, sequence)
		}
	}

	walk(t, nil)
}

type op = struct {
	kind string
	key  int
}

func runSequence(t *testing.T, sequence []op) {
	t.Helper()

	store := open(t)
	model := map[string]keystore.Record{}
	records := make([]keystore.Record, 2)
	blobs := make([][]byte, 2)
	records[0], blobs[0] = key(t, "first", 1)
	records[1], blobs[1] = key(t, "second", 2)

	for step, o := range sequence {
		record := records[o.key]

		var err error

		switch o.kind {
		case "create":
			err = store.Create(record, blobs[o.key])
			_, exists := model[record.Fingerprint]

			if exists != errors.Is(err, keystore.ErrExists) || (!exists && err != nil) {
				t.Fatalf("%v step %d create: exists=%v err=%v", sequence, step, exists, err)
			}

			if !exists {
				model[record.Fingerprint] = record
			}
		case "update":
			record.Policy.Namespaces = []string{"git", "file"}
			err = store.Update(record)
			_, exists := model[record.Fingerprint]

			if exists != (err == nil) || (!exists && !errors.Is(err, keystore.ErrNotFound)) {
				t.Fatalf("%v step %d update: exists=%v err=%v", sequence, step, exists, err)
			}

			if exists {
				model[record.Fingerprint] = record
			}
		case "delete":
			err = store.Delete(record.Fingerprint)
			_, exists := model[record.Fingerprint]

			if exists != (err == nil) || (!exists && !errors.Is(err, keystore.ErrNotFound)) {
				t.Fatalf("%v step %d delete: exists=%v err=%v", sequence, step, exists, err)
			}

			delete(model, record.Fingerprint)
		}

		list, err := store.List()
		if err != nil || len(list) != len(model) {
			t.Fatalf("%v step %d list: %d records, model %d, %v", sequence, step, len(list), len(model), err)
		}

		for _, got := range list {
			want, ok := model[got.Fingerprint]
			if !ok || !sameRecord(got, want) {
				t.Fatalf("%v step %d: store has %+v, model %+v", sequence, step, got, want)
			}
		}
	}
}
