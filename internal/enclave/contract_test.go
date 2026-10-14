// The contract of package enclave is its package comment, held to the
// hardware: these tests run only where an enclave answers (a real Mac, the
// process outside any sandbox) and skip, saying so, elsewhere; the keychain
// tests run only where the process carries the keychain-access-groups
// entitlement, which is the test binary wrapped in the development bundle
// (hack/test-hardware.sh), and skip elsewhere. CI runs in a virtual machine
// and skips both; the lanes are run on a real Mac before every release
// (docs/design.md, "Testing").
package enclave_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/forkcloser/taciturn/internal/enclave"
)

func requireEnclave(t *testing.T) {
	t.Helper()

	if !enclave.Available() {
		t.Skip("no Secure Enclave reachable from this process: a virtual machine, a sandbox, or no enclave")
	}
}

// requireKeychain skips where the process cannot store keys: no enclave,
// or no keychain-access-groups entitlement (a bare test binary).
func requireKeychain(t *testing.T) string {
	t.Helper()
	requireEnclave(t)

	group, err := enclave.AccessGroup()
	if err != nil {
		t.Skipf("no keychain access group, the test binary is not in the signed bundle: %v", err)
	}

	return group
}

// label is a unique keychain label for a test, removed when the test ends
// whether or not the test stored anything under it.
func label(t *testing.T) string {
	t.Helper()

	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}

	name := "taciturn-test-" + t.Name() + "-" + hex.EncodeToString(random[:])

	t.Cleanup(func() { _ = enclave.Delete(name) })

	return name
}

// verifies says whether (r, s) is a signature over SHA-256 of message by
// the key whose uncompressed point is public, checked with Go's own ECDSA.
func verifies(t *testing.T, public, message []byte, r, s *big.Int) bool {
	t.Helper()

	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), public)
	if err != nil {
		t.Fatalf("public key is not a P-256 point: %v", err)
	}

	digest := sha256.Sum256(message)

	return ecdsa.Verify(key, digest[:], r, s)
}

func generate(t *testing.T) *enclave.Key {
	t.Helper()

	key, err := enclave.Generate(enclave.ClassAfterFirstUnlock)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	return key
}

func TestGenerateSignVerify(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	for _, class := range []enclave.Class{enclave.ClassAfterFirstUnlock, enclave.ClassWhenUnlocked} {
		t.Run(className(class), func(t *testing.T) {
			t.Parallel()

			key, err := enclave.Generate(class)
			if class == enclave.ClassWhenUnlocked && errors.Is(err, enclave.ErrRefused) {
				// The contract itself: with the session locked the enclave
				// will not even make a key of this class (seen 2026-10-12,
				// screen locked, OSStatus -25308) while the other class
				// signs.
				t.Skipf("ClassWhenUnlocked refused, the session is locked: %v", err)
			}

			if err != nil {
				t.Fatal(err)
			}

			defer key.Close()

			if len(key.Public()) != enclave.PointSize || key.Public()[0] != 0x04 {
				t.Fatalf("public key %x", key.Public())
			}

			message := []byte("the quick brown fox")

			r, s, err := key.Sign(message)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			if !verifies(t, key.Public(), message, r, s) {
				t.Fatal("signature does not verify")
			}

			if verifies(t, key.Public(), []byte("another message"), r, s) {
				t.Fatal("signature verifies another message")
			}
		})
	}
}

func className(class enclave.Class) string {
	if class == enclave.ClassWhenUnlocked {
		return "when-unlocked"
	}

	return "after-first-unlock"
}

func TestTwoKeysDiffer(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	first := generate(t)
	defer first.Close()

	second := generate(t)
	defer second.Close()

	if bytes.Equal(first.Public(), second.Public()) {
		t.Fatal("two generated keys are the same")
	}
}

// The group the process is entitled to ends in the bundle identifier.
func TestAccessGroupEndsInTheIdentifier(t *testing.T) {
	t.Parallel()

	group := requireKeychain(t)

	if !strings.HasSuffix(group, "."+enclave.AccessGroupSuffix) || strings.Count(group, ".") < 3 {
		t.Fatalf("access group %q", group)
	}
}

// A stored key is found by its label, is the same key, and signs; deleted,
// it is gone and the label is free again.
func TestStoreLoadDelete(t *testing.T) {
	t.Parallel()
	requireKeychain(t)

	name := label(t)
	key := generate(t)
	public := key.Public()

	if err := key.Store(name); err != nil {
		t.Fatalf("store: %v", err)
	}

	key.Close()

	loaded, err := enclave.Load(name, public)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	defer loaded.Close()

	if !bytes.Equal(loaded.Public(), public) {
		t.Fatal("loaded key differs")
	}

	message := []byte("signed after reload from the keychain")

	r, s, err := loaded.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !verifies(t, public, message, r, s) {
		t.Fatal("signature by the reloaded key does not verify with the original public key")
	}

	if err := enclave.Delete(name); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := enclave.Load(name, public); !errors.Is(err, enclave.ErrNotFound) {
		t.Fatalf("load after delete: %v", err)
	}

	if err := enclave.Delete(name); !errors.Is(err, enclave.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

// A label is taken once: storing another key under it is ErrExists and the
// first key stays.
func TestStoreRefusesATakenLabel(t *testing.T) {
	t.Parallel()
	requireKeychain(t)

	name := label(t)

	first := generate(t)
	defer first.Close()

	if err := first.Store(name); err != nil {
		t.Fatal(err)
	}

	second := generate(t)
	defer second.Close()

	if err := second.Store(name); !errors.Is(err, enclave.ErrExists) {
		t.Fatalf("second store under the same label: %v", err)
	}

	loaded, err := enclave.Load(name, first.Public())
	if err != nil {
		t.Fatalf("the first key is not the one under the label: %v", err)
	}

	loaded.Close()
}

// Load refuses what is not the stored key: the wrong public key beside a
// good label is ErrMismatch and no key comes back; a label nothing carries
// is ErrNotFound.
func TestLoadRefusesTheWrongKey(t *testing.T) {
	t.Parallel()
	requireKeychain(t)

	name := label(t)
	key := generate(t)

	if err := key.Store(name); err != nil {
		t.Fatal(err)
	}

	key.Close()

	other := generate(t)
	otherPublic := other.Public()
	other.Close()

	if _, err := enclave.Load(name, otherPublic); !errors.Is(err, enclave.ErrMismatch) {
		t.Fatalf("other key's public half: %v", err)
	}

	if _, err := enclave.Load(label(t), key.Public()); !errors.Is(err, enclave.ErrNotFound) {
		t.Fatalf("unknown label: %v", err)
	}
}

// A v0.1 key, rebuilt from its wrapped blob, is imported into the keychain
// and is the same key afterwards (docs/design.md F17). The blob comes from
// the one place this package still reads one: a transient key's own,
// through the import of a key it made itself.
func TestImportIsTheSameKey(t *testing.T) {
	t.Parallel()
	requireKeychain(t)

	name := label(t)
	public, blob := transientKeyBlob(t)

	imported, err := enclave.Import(blob, public, name)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	defer imported.Close()

	if !bytes.Equal(imported.Public(), public) {
		t.Fatal("imported key differs")
	}

	loaded, err := enclave.Load(name, public)
	if err != nil {
		t.Fatalf("load after import: %v", err)
	}

	defer loaded.Close()

	message := []byte("signed by the imported key")

	r, s, err := loaded.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !verifies(t, public, message, r, s) {
		t.Fatal("the imported key's signature does not verify")
	}

	other := generate(t)
	otherPublic := other.Public()
	other.Close()

	if _, err := enclave.Import(blob, otherPublic, label(t)); !errors.Is(err, enclave.ErrMismatch) {
		t.Fatalf("import with another public key: %v", err)
	}

	garbage := append([]byte(nil), blob...)
	for i := range garbage {
		garbage[i] ^= 0x5A
	}

	if _, err := enclave.Import(garbage, public, label(t)); err == nil {
		t.Fatal("a corrupted blob imported")
	}
}

// The keychain item is found from another process entitled to the group:
// what the CLI stores, the agent loads.
func TestLoadInAnotherProcess(t *testing.T) {
	t.Parallel()
	requireKeychain(t)

	name := label(t)
	key := generate(t)
	public := key.Public()

	if err := key.Store(name); err != nil {
		t.Fatal(err)
	}

	key.Close()

	message := []byte("across processes")

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSignInChild$")

	cmd.Env = append(os.Environ(),
		"TACITURN_HELPER_LABEL="+name,
		"TACITURN_HELPER_PUBLIC="+base64.StdEncoding.EncodeToString(public),
		"TACITURN_HELPER_MESSAGE="+base64.StdEncoding.EncodeToString(message),
	)

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v: %s", err, out)
	}

	line := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "SIG "))

	parts := strings.Split(line, " ")
	if len(parts) != 2 {
		t.Fatalf("child output %q", out)
	}

	rBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	sBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	if !verifies(t, public, message, new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)) {
		t.Fatal("the child's signature does not verify with the parent's public key")
	}
}

// TestHelperSignInChild is the child of TestLoadInAnotherProcess: it loads
// the key by label from the environment, signs, and prints r and s.
func TestHelperSignInChild(t *testing.T) {
	t.Parallel()

	name := os.Getenv("TACITURN_HELPER_LABEL")
	if name == "" {
		t.Skip("not the child process")
	}

	public, err := base64.StdEncoding.DecodeString(os.Getenv("TACITURN_HELPER_PUBLIC"))
	if err != nil {
		t.Fatal(err)
	}

	message, err := base64.StdEncoding.DecodeString(os.Getenv("TACITURN_HELPER_MESSAGE"))
	if err != nil {
		t.Fatal(err)
	}

	key, err := enclave.Load(name, public)
	if err != nil {
		t.Fatal(err)
	}

	defer key.Close()

	r, s, err := key.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	// Printed first on standard output; the test runner's own lines follow.
	_, _ = os.Stdout.WriteString(
		"SIG " + base64.StdEncoding.EncodeToString(
			r.Bytes(),
		) + " " + base64.StdEncoding.EncodeToString(
			s.Bytes(),
		) + "\n",
	)
}

func TestRefusesBadArguments(t *testing.T) {
	t.Parallel()

	point := make([]byte, enclave.PointSize)
	point[0] = 0x04

	for _, bad := range []string{"", strings.Repeat("x", enclave.MaxLabel+1), "with\nnewline", "nul\x00"} {
		if _, err := enclave.Load(bad, point); !errors.Is(err, enclave.ErrInvalid) {
			t.Fatalf("load with label %q: %v", bad, err)
		}

		if err := enclave.Delete(bad); !errors.Is(err, enclave.ErrInvalid) {
			t.Fatalf("delete with label %q: %v", bad, err)
		}
	}

	if _, err := enclave.Load("fine", []byte{4, 1}); !errors.Is(err, enclave.ErrInvalid) {
		t.Fatalf("short public key: %v", err)
	}

	if _, err := enclave.Import(nil, point, "fine"); !errors.Is(err, enclave.ErrInvalid) {
		t.Fatalf("empty blob: %v", err)
	}

	_, err := enclave.Generate(enclave.Class(0))
	if !errors.Is(err, enclave.ErrInvalid) && !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("class 0: %v", err)
	}
}

// Without the entitlement, every keychain operation is ErrUnavailable and
// says why, which is what a bare binary and doctor see.
func TestWithoutTheEntitlement(t *testing.T) {
	t.Parallel()

	if _, err := enclave.AccessGroup(); err == nil {
		t.Skip("this process is entitled")
	}

	point := make([]byte, enclave.PointSize)
	point[0] = 0x04

	if _, err := enclave.Load("any", point); !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("load: %v", err)
	}

	if err := enclave.Delete("any"); !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("delete: %v", err)
	}
}

func TestSignAfterCloseIsRefused(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	key := generate(t)
	key.Close()
	key.Close()

	if _, _, err := key.Sign([]byte("x")); !errors.Is(err, enclave.ErrInvalid) {
		t.Fatalf("sign after close: %v", err)
	}

	if err := key.Store(label(t)); !errors.Is(err, enclave.ErrInvalid) && !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("store after close: %v", err)
	}
}

// transientKeyBlob makes a key the v0.1 way and hands back its public point
// and wrapped blob, through the package's own export for tests.
func transientKeyBlob(t *testing.T) (public, blob []byte) {
	t.Helper()

	key := generate(t)
	defer key.Close()

	return key.Public(), enclave.BlobForTest(key)
}
