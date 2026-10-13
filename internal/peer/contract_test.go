// The contract of package peer is its package comment, held to this
// process connecting to itself over a unix socket: the kernel answers for
// the peer's uid and pid, the framework for its path and signature. The
// tests need Security.framework and skip, saying so, where Identify says
// it is unavailable.
package peer_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/forkcloser/taciturn/internal/peer"
)

// selfConnection is a connected pair over a temporary socket: the server
// side sees this process as its peer.
func selfConnection(t *testing.T) *net.UnixConn {
	t.Helper()

	path := filepath.Join(t.TempDir(), "s")

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = client.Close() })

	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = server.Close() })

	return server
}

func identifySelf(t *testing.T) *peer.Identity {
	t.Helper()

	identity, err := peer.Identify(selfConnection(t))
	if errors.Is(err, peer.ErrUnavailable) {
		t.Skipf("peer identity unavailable here: %v", err)
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(identity.Close)

	return identity
}

func TestIdentifySelf(t *testing.T) {
	t.Parallel()

	identity := identifySelf(t)

	if identity.PID != os.Getpid() {
		t.Fatalf("pid %d, want %d", identity.PID, os.Getpid())
	}

	if identity.UID != uint32(os.Geteuid()) {
		t.Fatalf("uid %d, want %d", identity.UID, os.Geteuid())
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	want, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}

	got, err := filepath.EvalSymlinks(identity.Path)
	if err != nil {
		t.Fatalf("path %q: %v", identity.Path, err)
	}

	if got != want {
		t.Fatalf("path %q, want %q", got, want)
	}

	// The test binary carries the linker's ad-hoc signature: valid, with
	// the file's name as its identifier, and a cdhash.
	if !identity.ValidSignature || identity.Identifier == "" || identity.CDHash == "" {
		t.Fatalf("signature: %+v", identity)
	}
}

func TestParentsAreAboveThePeer(t *testing.T) {
	t.Parallel()

	identity := identifySelf(t)

	if len(identity.Parents) == 0 || identity.Parents[0].PID != os.Getppid() {
		t.Fatalf("parents %+v, want the first to be %d", identity.Parents, os.Getppid())
	}

	if len(identity.Parents) > peer.MaxParents {
		t.Fatalf("%d parents", len(identity.Parents))
	}
}

func TestSatisfies(t *testing.T) {
	t.Parallel()

	identity := identifySelf(t)

	// The identifier requirement holds for the ad-hoc signed test binary,
	// which is exactly why an identifier alone proves no origin.
	ok, err := identity.Satisfies(`identifier "` + identity.Identifier + `"`)
	if err != nil || !ok {
		t.Fatalf("own identifier: %v %v", ok, err)
	}

	ok, err = identity.Satisfies(`identifier "com.apple.ssh"`)
	if err != nil || ok {
		t.Fatalf("another identifier: %v %v", ok, err)
	}

	ok, err = identity.Satisfies("anchor apple")
	if err != nil || ok {
		t.Fatalf("anchor apple on an ad-hoc binary: %v %v", ok, err)
	}

	if _, err := identity.Satisfies("this is not a requirement ((("); !errors.Is(err, peer.ErrInvalid) {
		t.Fatalf("garbage requirement: %v", err)
	}

	if _, err := identity.Satisfies("anchor \xff apple"); !errors.Is(err, peer.ErrInvalid) {
		t.Fatalf("requirement that is not UTF-8: %v", err)
	}

	identity.Close()
	identity.Close()

	if _, err := identity.Satisfies("anchor apple"); !errors.Is(err, peer.ErrUnavailable) {
		t.Fatalf("after close: %v", err)
	}
}

// ValidRequirement answers from the parser alone: what Satisfies would
// evaluate parses, what it reports ErrInvalid for does not.
func TestValidRequirement(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"anchor apple",
		`anchor apple and identifier "com.apple.ssh"`,
		`identifier "org.forkcloser.ssh" and cdhash H"0123456789abcdef0123456789abcdef01234567"`,
	} {
		if err := peer.ValidRequirement(text); err != nil {
			if errors.Is(err, peer.ErrUnavailable) {
				t.Skip("built without the framework")
			}

			t.Fatalf("%q: %v", text, err)
		}
	}

	for _, text := range []string{"", "this is not a requirement (((", `identifier`, "anchor apple and", "anchor \xff\xfe apple"} {
		if err := peer.ValidRequirement(text); !errors.Is(err, peer.ErrInvalid) {
			t.Fatalf("%q: %v", text, err)
		}
	}
}
