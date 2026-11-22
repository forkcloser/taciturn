package cli_test

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The key commands that reach the enclave and the keychain, on the
// hardware and from the signed bundle: create, rotate named by the
// fingerprint, retire, delete. Every key the test makes leaves the keychain
// with it, whatever fails on the way.
func TestKeyLifecycleOnTheHardware(t *testing.T) {
	t.Parallel()

	if !enclave.Available() {
		t.Skip("no Secure Enclave reachable from this process")
	}

	if _, err := enclave.AccessGroup(); err != nil {
		t.Skipf("no keychain access group, the test binary is not in the signed bundle: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "keys")

	t.Cleanup(func() {
		store, err := keystore.Open(dir)
		if err != nil {
			return
		}

		records, err := store.List()
		if err != nil {
			return
		}

		for _, record := range records {
			_ = enclave.Delete(record.Fingerprint)
		}
	})

	fingerprint := regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)

	code, out, errOut := run(t, "key", "create", "bot", "-store", dir, "-use", "locked", "-peers", "any")
	if code != 0 {
		t.Fatalf("create: exit %d: %s", code, errOut)
	}

	first := fingerprint.FindString(out)
	if first == "" || !strings.Contains(out, "created bot "+first) {
		t.Fatalf("create: %s", out)
	}

	inKeychain(t, dir, first, true)

	// Rotation named by the fingerprint: the successor takes the record's
	// name, not the argument.
	code, out, errOut = run(t, "key", "rotate", first, "-store", dir)
	if code != 0 {
		t.Fatalf("rotate: exit %d: %s", code, errOut)
	}

	found := fingerprint.FindAllString(out, -1)
	if len(found) < 2 || found[0] == first || found[1] != first {
		t.Fatalf("rotate: %s", out)
	}

	second := found[0]

	// The key that gave up its name, as the rotation renamed it.
	old := regexp.MustCompile(`bot@\d{8}`).FindString(out)
	if old == "" {
		t.Fatalf("rotate: no name for the rotated key: %s", out)
	}

	inKeychain(t, dir, second, true)

	code, out, _ = run(t, "key", "list", "-store", dir, "-format", "ssh")
	if code != 0 || strings.Count(out, "\n") != 2 || !strings.Contains(out, " bot\n") ||
		!strings.Contains(out, " bot@") {
		t.Fatalf("list after the rotation: exit %d: %s", code, out)
	}

	code, out, errOut = run(t, "key", "retire", old, "-store", dir)
	if code != 0 || !strings.Contains(out, "retired "+old) {
		t.Fatalf("retire: exit %d: %s %s", code, out, errOut)
	}

	for name, key := range map[string]string{old: first, "bot": second} {
		code, _, errOut = run(t, "key", "delete", name, "-store", dir, "-yes")
		if code != 0 || errOut != "" {
			t.Fatalf("delete %s: exit %d: %s", name, code, errOut)
		}

		inKeychain(t, dir, key, false)
	}

	code, out, _ = run(t, "key", "list", "-store", dir, "-format", "ssh")
	if code != 0 || out != "" {
		t.Fatalf("list after the deletions: exit %d: %s", code, out)
	}
}

// inKeychain says the keychain holds, or no longer holds, the key of the
// record with this fingerprint.
func inKeychain(t *testing.T, dir, fingerprint string, want bool) {
	t.Helper()

	store, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	record, err := store.Get(fingerprint)

	switch {
	case want && err != nil:
		t.Fatalf("record of %s: %v", fingerprint, err)
	case !want:
		if !errors.Is(err, keystore.ErrNotFound) {
			t.Fatalf("record of %s after its deletion: %v", fingerprint, err)
		}

		// The label alone decides here: any well-formed point will do.
		_, err = enclave.Load(fingerprint, append([]byte{4}, make([]byte, enclave.PointSize-1)...))
		if !errors.Is(err, enclave.ErrNotFound) {
			t.Fatalf("keychain item of %s after its deletion: %v", fingerprint, err)
		}

		return
	}

	point, err := protocol.ECDSAP256PublicKeyPoint(record.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := enclave.Load(fingerprint, point)
	if err != nil {
		t.Fatalf("keychain item of %s: %v", fingerprint, err)
	}

	key.Close()
}
