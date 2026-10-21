package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/agent"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// OpenSSH's own clients at the socket, as the design's end-to-end procedure
// ran them by hand: ssh-add lists what the agent serves and is refused what
// it must not do, and ssh-keygen -Y sign asks for the one signed-data shape
// no Go client produces, so its request is the oracle for the SSHSIG layout
// the agent parses and judges. The allowed path ends at the enclave, which
// the store's blob is not from; the audit record says the policy allowed it.

// requireOpenSSH is the two clients, or a skip that names which is missing.
func requireOpenSSH(t *testing.T) (sshAdd, sshKeygen string) {
	t.Helper()

	sshAdd, err := exec.LookPath("ssh-add")
	if err != nil {
		t.Skipf("no ssh-add on the PATH: %v", err)
	}

	sshKeygen, err = exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("no ssh-keygen on the PATH: %v", err)
	}

	return sshAdd, sshKeygen
}

// records collects the agent's log as JSON lines, read back decoded.
type records struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *records) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.buf.Write(p)
}

// requests are the audit records of sign requests, oldest first.
func (r *records) requests(t *testing.T) []map[string]any {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(r.buf.String()), "\n") {
		if line == "" {
			continue
		}

		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode the log record %q: %v", line, err)
		}

		if record["msg"] == "request" && record["request"] == "sign" {
			out = append(out, record)
		}
	}

	return out
}

// startLogged is start with the agent's log kept for reading.
func startLogged(t *testing.T) (*rig, *records) {
	t.Helper()

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "a.sock")
	logged := &records{}

	server, err := agent.Listen(socket, agent.Config{
		Store:       store,
		Logger:      slog.New(slog.NewJSONHandler(logged, nil)),
		IdleTimeout: 5 * time.Second,
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

	return &rig{store: store, server: server, socket: socket}, logged
}

// client runs one OpenSSH command against the agent's socket and returns
// its stdout, the oracle, alone; what it wrote on stderr (a proxy's
// warning, its own complaint) comes back only with a failure, for the
// message.
func client(t *testing.T, socket, binary string, args ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)

	out, err := cmd.Output()

	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return string(out) + string(exit.Stderr), err
	}

	return string(out), err
}

func TestOpenSSHClientsAtTheSocket(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	sshAdd, sshKeygen := requireOpenSSH(t)
	r, logged := startLogged(t)
	h := newHost(t)

	record := botKey(t, "bot", github(h))
	if err := r.store.Create(record); err != nil {
		t.Fatal(err)
	}

	public, err := ssh.ParsePublicKey(record.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	pubFile := filepath.Join(dir, "bot.pub")

	if err := os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(public), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("ssh-add -L lists the key as ssh-keygen spells it", func(t *testing.T) {
		t.Parallel()

		out, err := client(t, r.socket, sshAdd, "-L")
		if err != nil {
			t.Fatalf("ssh-add -L: %v\n%s", err, out)
		}

		want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " bot"
		if strings.TrimSpace(out) != want {
			t.Fatalf("ssh-add -L printed %q, want %q", strings.TrimSpace(out), want)
		}
	})

	t.Run("ssh-add -l prints the fingerprint the package computes", func(t *testing.T) {
		t.Parallel()

		out, err := client(t, r.socket, sshAdd, "-l")
		if err != nil {
			t.Fatalf("ssh-add -l: %v\n%s", err, out)
		}

		if !strings.Contains(out, protocol.Fingerprint(record.PublicKey)) || !strings.Contains(out, "bot") {
			t.Fatalf(
				"ssh-add -l printed %q, want the fingerprint %s and the name",
				out,
				protocol.Fingerprint(record.PublicKey),
			)
		}
	})

	t.Run("ssh-add cannot add, remove or remove all", func(t *testing.T) {
		t.Parallel()

		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			t.Fatal(err)
		}

		keyFile := filepath.Join(t.TempDir(), "id")
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}

		for name, args := range map[string][]string{
			"add":        {keyFile},
			"remove":     {"-d", pubFile},
			"remove all": {"-D"},
		} {
			if out, addErr := client(t, r.socket, sshAdd, args...); addErr == nil {
				t.Fatalf("ssh-add %s succeeded:\n%s", name, out)
			}
		}

		// The key is still served after each refusal.
		out, listErr := client(t, r.socket, sshAdd, "-L")
		if listErr != nil || !strings.Contains(out, " bot") {
			t.Fatalf("ssh-add -L after the refusals: %v\n%s", listErr, out)
		}
	})

	t.Run("ssh-keygen -Y sign is judged by namespace", func(t *testing.T) {
		t.Parallel()

		message := filepath.Join(t.TempDir(), "message")
		if err := os.WriteFile(message, []byte("a commit\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if out, err := client(
			t,
			r.socket,
			sshKeygen,
			"-Y",
			"sign",
			"-U",
			"-f",
			pubFile,
			"-n",
			"file",
			message,
		); err == nil {
			t.Fatalf("ssh-keygen signed in a namespace the policy does not allow:\n%s", out)
		}

		// git is allowed: the policy says so and the enclave, which this
		// key is not from, refuses; ssh-keygen sees the one failure.
		if out, err := client(
			t,
			r.socket,
			sshKeygen,
			"-Y",
			"sign",
			"-U",
			"-f",
			pubFile,
			"-n",
			"git",
			message,
		); err == nil {
			t.Fatalf("ssh-keygen got a signature from a blob that is not the enclave's:\n%s", out)
		}

		seen := map[string]map[string]any{}

		for _, request := range logged.requests(t) {
			if ns, ok := request["namespace"].(string); ok {
				seen[ns] = request
			}
		}

		refused, ok := seen["file"]
		if !ok || refused["data"] != "sshsig" || refused["rule"] != policy.RuleNamespace ||
			refused["outcome"] != "refuse" {
			t.Fatalf("the file namespace: %v", refused)
		}

		allowed, ok := seen["git"]
		if !ok || allowed["data"] != "sshsig" || allowed["rule"] != policy.RuleAllowedSSHSig ||
			allowed["outcome"] != "refuse" {
			t.Fatalf("the git namespace: %v", allowed)
		}

		reason, ok := allowed["error"].(string)
		if !ok || (!strings.Contains(reason, "keychain") && !strings.Contains(reason, "enclave")) {
			t.Fatalf("the allowed request did not end at the enclave: %v", allowed)
		}
	})
}
