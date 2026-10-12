// The contract of package enclave is its package comment, held to the
// hardware: these tests run only where an enclave answers (a real Mac, the
// process outside any sandbox) and skip, saying so, elsewhere. CI runs in
// a virtual machine and skips; the lane is run on a real Mac before every
// release (docs/design.md, "Testing").
package enclave_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
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

			if len(key.Blob()) == 0 {
				t.Fatal("empty blob")
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

	if bytes.Equal(first.Public(), second.Public()) || bytes.Equal(first.Blob(), second.Blob()) {
		t.Fatal("two generated keys are the same")
	}
}

func TestLoadIsTheSameKey(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	key := generate(t)
	blob, public := key.Blob(), key.Public()
	key.Close()

	loaded, err := enclave.Load(blob, public)
	if err != nil {
		t.Fatal(err)
	}

	defer loaded.Close()

	if !bytes.Equal(loaded.Public(), public) || !bytes.Equal(loaded.Blob(), blob) {
		t.Fatal("loaded key differs")
	}

	message := []byte("signed after reload")

	r, s, err := loaded.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !verifies(t, public, message, r, s) {
		t.Fatal("signature by the reloaded key does not verify with the original public key")
	}
}

// The blob round-trips through another process: the key the second
// process loads is the first process's key, which is what a store and an
// agent in different processes rely on.
func TestLoadInAnotherProcess(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	key := generate(t)
	blob, public := key.Blob(), key.Public()
	key.Close()

	message := []byte("across processes")

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSignInChild$")

	cmd.Env = append(os.Environ(),
		"TACITURN_HELPER_BLOB="+base64.StdEncoding.EncodeToString(blob),
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
// the blob from the environment, signs, and prints r and s.
func TestHelperSignInChild(t *testing.T) {
	t.Parallel()

	blobText := os.Getenv("TACITURN_HELPER_BLOB")
	if blobText == "" {
		t.Skip("not the child process")
	}

	blob, err := base64.StdEncoding.DecodeString(blobText)
	if err != nil {
		t.Fatal(err)
	}

	public, err := base64.StdEncoding.DecodeString(os.Getenv("TACITURN_HELPER_PUBLIC"))
	if err != nil {
		t.Fatal(err)
	}

	message, err := base64.StdEncoding.DecodeString(os.Getenv("TACITURN_HELPER_MESSAGE"))
	if err != nil {
		t.Fatal(err)
	}

	key, err := enclave.Load(blob, public)
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

// Load refuses what is not the stored key: the wrong public key beside a
// good blob is ErrMismatch and no key comes back; a blob the enclave does
// not know is ErrInvalid or ErrInternal, never a key.
func TestLoadRefusesTheWrongKey(t *testing.T) {
	t.Parallel()
	requireEnclave(t)

	key := generate(t)
	blob, public := key.Blob(), key.Public()
	key.Close()

	other := generate(t)
	otherPublic := other.Public()
	other.Close()

	if _, err := enclave.Load(blob, otherPublic); !errors.Is(err, enclave.ErrMismatch) {
		t.Fatalf("other key's public half: %v", err)
	}

	garbage := append([]byte(nil), blob...)
	for i := range garbage {
		garbage[i] ^= 0x5A
	}

	loaded, err := enclave.Load(garbage, public)
	if err == nil {
		loaded.Close()
		t.Fatal("a corrupted blob loaded")
	}

	if !errors.Is(err, enclave.ErrInvalid) && !errors.Is(err, enclave.ErrInternal) {
		t.Fatalf("corrupted blob: %v", err)
	}
}

func TestLoadRefusesBadArguments(t *testing.T) {
	t.Parallel()

	if _, err := enclave.Load(nil, make([]byte, enclave.PointSize)); !errors.Is(err, enclave.ErrInvalid) {
		t.Fatalf("empty blob: %v", err)
	}

	err := func() error { _, err := enclave.Load([]byte{1}, make([]byte, enclave.PointSize)); return err }()
	if !errors.Is(err, enclave.ErrInvalid) && !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("public key without the 0x04 prefix: %v", err)
	}

	_, err = enclave.Load([]byte{1}, []byte{4, 1})
	if !errors.Is(err, enclave.ErrInvalid) {
		t.Fatalf("short public key: %v", err)
	}

	_, err = enclave.Generate(enclave.Class(0))
	if !errors.Is(err, enclave.ErrInvalid) && !errors.Is(err, enclave.ErrUnavailable) {
		t.Fatalf("class 0: %v", err)
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
}
