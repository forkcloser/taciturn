// The contract of package agent is its package comment, held to a real
// client: x/crypto/ssh/agent speaking to the server over a temporary
// socket, with a key store of this test's making. What needs the enclave
// (a signature that is allowed) runs on the hardware only, in
// hardware_test.go; everything else, listing, binding, every refusal,
// runs anywhere Security.framework identifies a peer.
package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/forkcloser/taciturn/internal/agent"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/peer"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// host is a server the client may be bound to: an ed25519 host key and
// the proof it makes for a session.
type host struct {
	signer ssh.Signer
	blob   []byte
}

func newHost(t *testing.T) host {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}

	return host{signer: signer, blob: signer.PublicKey().Marshal()}
}

// bind is the session-bind extension contents for this host and session.
func (h host) bind(t *testing.T, sessionID []byte, forwarding bool) []byte {
	t.Helper()

	signature, err := h.signer.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{h.blob, sessionID, ssh.Marshal(signature), forwarding})
}

// botKey is a record whose public key is a real P-256 point, so a client
// can parse it, and whose blob is not an enclave's: a signature the policy
// allows fails at the enclave, which is what the tests here rely on.
func botKey(t *testing.T, name string, pol policy.Policy) (keystore.Record, []byte) {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	blob, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	return keystore.Record{
		Fingerprint: protocol.Fingerprint(blob),
		Name:        name,
		PublicKey:   blob,
		Class:       keystore.ClassAfterFirstUnlock,
		Created:     time.Date(2026, time.October, 12, 16, 0, 0, 0, time.UTC),
		Policy:      pol,
	}, bytes.Repeat([]byte{0xAB}, 324)
}

func sessionID() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func userauth(sid []byte, user string, keyBlob []byte) []byte {
	return ssh.Marshal(struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		Sig       bool
		Algorithm string
		Key       []byte
	}{sid, 50, user, "ssh-connection", "publickey", true, protocol.AlgorithmECDSAP256, keyBlob})
}

func sshsig(namespace string) []byte {
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    []byte
	}{namespace, "", "sha512", bytes.Repeat([]byte{7}, 64)})...)
}

// rig is a running agent with a store, and a way to connect to it.
type rig struct {
	store  *keystore.Store
	server *agent.Server
	socket string
}

func start(t *testing.T) *rig {
	t.Helper()

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "a.sock")

	server, err := agent.Listen(socket, agent.Config{
		Store:       store,
		Logger:      slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		IdleTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- server.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}

		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Close: %v", err)
		}
	})

	return &rig{store: store, server: server, socket: socket}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(bytes.TrimRight(p, "\n")))

	return len(p), nil
}

func (r *rig) client(t *testing.T) sshagent.ExtendedAgent {
	t.Helper()

	conn, err := net.Dial("unix", r.socket)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	return sshagent.NewClient(conn)
}

func requirePeerIdentity(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "p")

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = listener.Close() }()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = client.Close() }()

	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = server.Close() }()

	identity, err := peer.Identify(server)
	if errors.Is(err, peer.ErrUnavailable) {
		t.Skipf("peer identity unavailable here: %v", err)
	}

	if err != nil {
		t.Fatal(err)
	}

	identity.Close()
}

func github(h host) policy.Policy {
	return policy.Policy{
		Destinations: []policy.Destination{{User: "git", Host: "github.com", HostKeys: [][]byte{h.blob}}},
		Namespaces:   []string{"git"},
		Peers:        []string{policy.PeerAny},
	}
}

func TestListenRefusals(t *testing.T) {
	t.Parallel()

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = agent.Listen(filepath.Join(dir, "a.sock"), agent.Config{}); !errors.Is(err, agent.ErrInvalid) {
		t.Fatalf("no store: %v", err)
	}

	file := filepath.Join(dir, "file")
	if err = os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err = agent.Listen(file, agent.Config{Store: store}); !errors.Is(err, agent.ErrInvalid) {
		t.Fatalf("a regular file at the socket path: %v", err)
	}

	first, err := agent.Listen(filepath.Join(dir, "a.sock"), agent.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = first.Close() }()

	if _, err = agent.Listen(
		filepath.Join(dir, "a.sock"),
		agent.Config{Store: store},
	); !errors.Is(
		err,
		agent.ErrBusy,
	) {
		t.Fatalf("second agent on the socket: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "a.sock"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	t.Parallel()

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "a.sock")

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	stale.SetUnlinkOnClose(false)
	_ = stale.Close()

	server, err := agent.Listen(socket, agent.Config{Store: store})
	if err != nil {
		t.Fatalf("over a stale socket: %v", err)
	}

	_ = server.Close()
}

func TestListingFollowsTheBinding(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)
	h := newHost(t)
	other := newHost(t)

	record, blob := botKey(t, "bot", github(h))
	if err := r.store.Create(record, blob); err != nil {
		t.Fatal(err)
	}

	retired, retiredBlob := botKey(t, "old", github(h))
	when := time.Now()
	retired.Retired = &when

	if err := r.store.Create(retired, retiredBlob); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		bind   []byte
		listed int
	}{
		"unbound":              {nil, 1},
		"bound to the host":    {h.bind(t, sessionID(), false), 1},
		"bound to another":     {other.bind(t, sessionID(), false), 0},
		"bound for forwarding": {h.bind(t, sessionID(), true), 0},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := r.client(t)

			if c.bind != nil {
				if _, err := client.Extension(protocol.ExtensionSessionBind, c.bind); err != nil {
					t.Fatalf("bind: %v", err)
				}
			}

			keys, err := client.List()
			if err != nil {
				t.Fatal(err)
			}

			if len(keys) != c.listed {
				t.Fatalf("listed %d keys, want %d", len(keys), c.listed)
			}

			if c.listed == 1 && (keys[0].Comment != "bot" || !bytes.Equal(keys[0].Marshal(), record.PublicKey)) {
				t.Fatalf("listed %+v", keys[0])
			}
		})
	}
}

func TestBindingIsVerified(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)
	h := newHost(t)

	record, blob := botKey(t, "bot", github(h))
	if err := r.store.Create(record, blob); err != nil {
		t.Fatal(err)
	}

	forged := h.bind(t, sessionID(), false)
	forged[len(forged)-10] ^= 0xFF // inside the signature

	cases := map[string][]byte{
		"forged proof": forged,
		"malformed":    {1, 2, 3},
		"empty":        {},
	}

	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := r.client(t)

			if _, err := client.Extension(protocol.ExtensionSessionBind, contents); err == nil {
				t.Fatal("a bad binding was accepted")
			}

			// A refused binding kills the connection for every key.
			keys, err := client.List()
			if err != nil {
				t.Fatal(err)
			}

			if len(keys) != 0 {
				t.Fatalf("listed %d keys after a refused binding", len(keys))
			}
		})
	}

	t.Run("rebinding", func(t *testing.T) {
		t.Parallel()

		client := r.client(t)
		first := h.bind(t, sessionID(), false)

		if _, err := client.Extension(protocol.ExtensionSessionBind, first); err != nil {
			t.Fatal(err)
		}

		if _, err := client.Extension(protocol.ExtensionSessionBind, first); err != nil {
			t.Fatalf("the same binding again: %v", err)
		}

		if _, err := client.Extension(
			protocol.ExtensionSessionBind,
			h.bind(t, bytes.Repeat([]byte{9}, 32), false),
		); err == nil {
			t.Fatal("a second, different binding was accepted")
		}

		keys, err := client.List()
		if err != nil || len(keys) != 0 {
			t.Fatalf("after a refused rebind: %d keys, %v", len(keys), err)
		}
	})
}

func TestSignatureRefusals(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)
	h := newHost(t)

	record, blob := botKey(t, "bot", github(h))
	if err := r.store.Create(record, blob); err != nil {
		t.Fatal(err)
	}

	key, err := ssh.ParsePublicKey(record.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	unknown, _ := botKey(t, "unknown", github(h))

	unknownKey, err := ssh.ParsePublicKey(unknown.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		bind []byte
		key  ssh.PublicKey
		data []byte
	}{
		"userauth unbound":            {nil, key, userauth(sessionID(), "git", record.PublicKey)},
		"sshsig in another namespace": {nil, key, sshsig("file")},
		"unknown key":                 {nil, unknownKey, sshsig("git")},
		"userauth for another session": {
			h.bind(t, sessionID(), false),
			key,
			userauth(bytes.Repeat([]byte{9}, 32), "git", record.PublicKey),
		},
		"userauth as another user": {
			h.bind(t, sessionID(), false),
			key,
			userauth(sessionID(), "root", record.PublicKey),
		},
		"sshsig on a bound connection": {h.bind(t, sessionID(), false), key, sshsig("git")},
		"forwarded": {
			h.bind(t, sessionID(), true),
			key,
			userauth(sessionID(), "git", record.PublicKey),
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := r.client(t)

			if c.bind != nil {
				if _, err := client.Extension(protocol.ExtensionSessionBind, c.bind); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := client.Sign(c.key, c.data); err == nil {
				t.Fatal("a refused signature was made")
			}
		})
	}
}

// What the policy allows reaches the enclave, which this store's blob is
// not from: the client sees a failure, the log says the enclave refused.
// The allowed path end to end is hardware_test.go.
func TestAllowedSignatureNeedsTheEnclave(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)
	h := newHost(t)

	record, blob := botKey(t, "bot", github(h))
	if err := r.store.Create(record, blob); err != nil {
		t.Fatal(err)
	}

	key, err := ssh.ParsePublicKey(record.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	client := r.client(t)
	if _, err := client.Sign(key, sshsig("git")); err == nil {
		t.Fatal("a signature came from a blob that is not the enclave's")
	}
}

func TestPeerPolicy(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	r := start(t)
	h := newHost(t)

	own := github(h)
	own.Peers = []string{policy.PeerPathPrefix + executable}
	ownRecord, ownBlob := botKey(t, "own", own)

	if err = r.store.Create(ownRecord, ownBlob); err != nil {
		t.Fatal(err)
	}

	foreign := github(h)
	foreign.Peers = []string{policy.PeerPathPrefix + "/usr/bin/ssh", `anchor apple and identifier "com.apple.ssh"`}
	foreignRecord, foreignBlob := botKey(t, "foreign", foreign)

	if err = r.store.Create(foreignRecord, foreignBlob); err != nil {
		t.Fatal(err)
	}

	client := r.client(t)

	foreignKey, err := ssh.ParsePublicKey(foreignRecord.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Sign(foreignKey, sshsig("git")); err == nil {
		t.Fatal("a key for another peer signed for this process")
	}
	// The own key passes the policy and fails at the enclave: covered by
	// TestAllowedSignatureNeedsTheEnclave and the hardware lane.
}

func TestOtherRequestsAreRefused(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)
	client := r.client(t)

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err = client.Add(sshagent.AddedKey{PrivateKey: private}); err == nil {
		t.Fatal("add was accepted")
	}

	if err = client.RemoveAll(); err == nil {
		t.Fatal("remove-all was accepted")
	}

	if err = client.Lock([]byte("x")); err == nil {
		t.Fatal("lock was accepted")
	}

	if _, err = client.Extension("nothing@example.com", nil); err == nil {
		t.Fatal("an unknown extension was accepted")
	}

	supported, err := client.Extension(protocol.ExtensionQuery, nil)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if !bytes.Contains(supported, []byte(protocol.ExtensionSessionBind)) {
		t.Fatalf("query answer %q", supported)
	}
}

func TestIdleConnectionIsClosed(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r := start(t)

	conn, err := net.Dial("unix", r.socket)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	if err = conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the idle connection stayed open")
	} else if time.Now().After(deadline) {
		t.Fatal("the agent did not close the idle connection")
	}
}

// shortDir is a temporary directory with a short path: a socket path is
// bounded at 104 bytes, and a test's own TempDir carries the test's name.
func shortDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "tc") //nolint:usetesting // sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return dir
}
