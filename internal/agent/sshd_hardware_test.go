package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The design's local-sshd leg, hardware lane: forkcloser/openssh's sshd on
// a loopback port with a host key of this test's making, and its ssh as the
// one real client that binds the session, asks for the host-bound
// user-authentication signature, and forwards the agent. The sandbox
// refuses sshd's privilege separation, so this runs where the enclave
// does. The client is pinned to the agent's key (IdentitiesOnly with the
// public key file, no user configuration), so no other key on the machine
// is ever asked.

// openSSHRoot is the fork's install directory, named by TACITURN_OPENSSH,
// with bin, sbin and libexec under it, or a skip naming what is missing.
func openSSHRoot(t *testing.T) string {
	t.Helper()

	root := os.Getenv("TACITURN_OPENSSH")
	if root == "" {
		t.Skip("TACITURN_OPENSSH is unset: the fork's install directory, with sbin/sshd")
	}

	for _, rel := range []string{
		"bin/ssh",
		"bin/ssh-add",
		"bin/ssh-keygen",
		"sbin/sshd",
		"libexec/sshd-session",
		"libexec/sshd-auth",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Skipf("TACITURN_OPENSSH=%s: %v", root, err)
		}
	}

	return root
}

// sshd is the fork's server on the loopback, up until the test ends.
type sshd struct {
	port    string
	hostKey ssh.PublicKey
}

// startSSHD runs sshd -D as this user with a fresh ed25519 host key and
// the authorized keys file given, and returns once it answers on its port.
func startSSHD(t *testing.T, root, authorizedKeys string) sshd {
	t.Helper()

	dir := shortDir(t)
	hostKeyFile := filepath.Join(dir, "host")

	keygen := exec.CommandContext(t.Context(), filepath.Join(root, "bin", "ssh-keygen"),
		"-q", "-t", "ed25519", "-N", "", "-C", "test host", "-f", hostKeyFile)
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen for the host key: %v\n%s", err, out)
	}

	hostPub, err := os.ReadFile(hostKeyFile + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(hostPub)
	if err != nil {
		t.Fatal(err)
	}

	port := freePort(t)

	// Paths are quoted: the fork's install directory has a space in it.
	config := strings.Join([]string{
		"Port " + port,
		"ListenAddress 127.0.0.1",
		"HostKey " + strconv.Quote(hostKeyFile),
		"PidFile none",
		"AuthorizedKeysFile " + strconv.Quote(authorizedKeys),
		"StrictModes no",
		"PubkeyAuthentication yes",
		"PubkeyAcceptedAlgorithms " + protocol.AlgorithmECDSAP256,
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"AllowAgentForwarding yes",
		"PermitTTY no",
		"SshdSessionPath " + strconv.Quote(filepath.Join(root, "libexec", "sshd-session")),
		"SshdAuthPath " + strconv.Quote(filepath.Join(root, "libexec", "sshd-auth")),
		"LogLevel ERROR",
	}, "\n") + "\n"

	configFile := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	var stderr bytes.Buffer

	server := exec.CommandContext(ctx, filepath.Join(root, "sbin", "sshd"), "-D", "-e", "-f", configFile)
	server.Stderr = &stderr
	// A session child still holding stderr must not hold the cleanup.
	server.WaitDelay = 5 * time.Second

	if err := server.Start(); err != nil {
		t.Fatalf("sshd: %v", err)
	}

	t.Cleanup(func() {
		cancel()

		_ = server.Wait()

		if t.Failed() && stderr.Len() > 0 {
			t.Logf("sshd stderr:\n%s", stderr.String())
		}
	})

	deadline := time.Now().Add(10 * time.Second)

	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			banner := make([]byte, 7)

			_, err = io.ReadFull(conn, banner)
			_ = conn.Close()

			if err == nil && string(banner) == "SSH-2.0" {
				return sshd{port: port, hostKey: hostKey}
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("sshd did not answer on 127.0.0.1:%s: %v\n%s", port, err, stderr.String())
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// freePort is a loopback port nothing listens on right now.
func freePort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	return port
}

// sshClient is the fork's ssh with the agent's socket as its only identity
// source: no user configuration, no identity file but the agent key's
// public half, and the server's host key pinned per run.
type sshClient struct {
	root     string
	socket   string
	pubFile  string
	username string
}

// run connects to the server and runs the command, with or without the
// agent forwarded; the output comes back with stderr on failure.
func (c sshClient) run(t *testing.T, server sshd, forward bool, command ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	forwarding := "no"
	if forward {
		forwarding = "yes"
	}

	args := []string{
		"-F", "none",
		"-o", "IdentityAgent=" + c.socket,
		"-o", "IdentitiesOnly=yes",
		"-i", c.pubFile,
		"-o", "UserKnownHostsFile=" + knownHostsFor(t, shortDir(t), server),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PubkeyAcceptedAlgorithms=" + protocol.AlgorithmECDSAP256,
		"-o", "PreferredAuthentications=publickey",
		"-o", "BatchMode=yes",
		"-o", "ForwardAgent=" + forwarding,
		"-o", "LogLevel=ERROR",
		"-p", server.port,
		c.username + "@127.0.0.1",
	}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, filepath.Join(c.root, "bin", "ssh"), args...)
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH"), "USER=" + c.username}

	out, err := cmd.Output()

	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return string(out) + string(exit.Stderr), err
	}

	return string(out), err
}

// knownHostsFor pins the server's host key for the client.
func knownHostsFor(t *testing.T, dir string, server sshd) string {
	t.Helper()

	path := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", server.port, ssh.MarshalAuthorizedKey(server.hostKey))

	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// entries are the audit records of one request kind, oldest first.
func (r *records) entries(t *testing.T, request string) []map[string]any {
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

		if record["msg"] == "request" && record["request"] == request {
			out = append(out, record)
		}
	}

	return out
}

// last is the newest record of a request kind, or a failure naming it.
func last(t *testing.T, logged *records, request string) map[string]any {
	t.Helper()

	entries := logged.entries(t, request)
	if len(entries) == 0 {
		t.Fatalf("no %s record in the agent's log", request)
	}

	return entries[len(entries)-1]
}

func TestLocalSSHD(t *testing.T) {
	t.Parallel()

	if !enclave.Available() {
		t.Skip("no Secure Enclave reachable from this process")
	}

	if _, err := enclave.AccessGroup(); err != nil {
		t.Skipf("no keychain access group, the test binary is not in the signed bundle: %v", err)
	}

	root := openSSHRoot(t)

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	r, logged := startLogged(t)

	made, err := enclave.Generate(enclave.ClassAfterFirstUnlock)
	if err != nil {
		t.Fatal(err)
	}

	defer made.Close()

	public, err := protocol.ECDSAP256PublicKey(made.Public())
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ssh.ParsePublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	dir := shortDir(t)
	pubFile := filepath.Join(dir, "bot.pub")

	if err = os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(parsed), 0o600); err != nil {
		t.Fatal(err)
	}

	// Two servers: the policy names the first's host key, not the second's.
	allowed := startSSHD(t, root, pubFile)
	other := startSSHD(t, root, pubFile)

	record := botKey(t, "bot", policy.Policy{
		Destinations: []policy.Destination{
			{User: me.Username, Host: "127.0.0.1", HostKeys: [][]byte{allowed.hostKey.Marshal()}},
		},
		Peers: []string{policy.PeerAny},
	})
	record.PublicKey = public
	record.Fingerprint = protocol.Fingerprint(public)

	if err = made.Store(record.Fingerprint); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = enclave.Delete(record.Fingerprint) })

	if err = r.store.Create(record); err != nil {
		t.Fatal(err)
	}

	client := sshClient{root: root, socket: r.socket, pubFile: pubFile, username: me.Username}

	// The legs run in order, each reading the records the one before left.
	allowedDestination(t, client, allowed, logged)
	unnamedHostKey(t, client, other, logged)
	forwardedAgent(t, client, allowed, logged)
}

// allowedDestination: the login the policy names succeeds on a signature
// the agent made for a host-bound user-authentication request.
func allowedDestination(t *testing.T, client sshClient, server sshd, logged *records) {
	t.Helper()

	out, err := client.run(t, server, false, "echo", "ok")
	if err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("ssh to the allowed server: %v\n%s", err, out)
	}

	sign := last(t, logged, "sign")
	if sign["outcome"] != "allow" || sign["rule"] != policy.RuleAllowedAuth ||
		sign["user"] != client.username || sign["data"] != "userauth" {
		t.Fatalf("the signature the server accepted: %v", sign)
	}

	bind := last(t, logged, "session-bind")
	if bind["outcome"] != "allow" || bind["forwarding"] != false ||
		bind["host"] != protocol.Fingerprint(server.hostKey.Marshal()) {
		t.Fatalf("the binding: %v", bind)
	}
}

// unnamedHostKey: bound to a server whose host key the policy does not
// name, the agent lists nothing and is asked to sign nothing.
func unnamedHostKey(t *testing.T, client sshClient, server sshd, logged *records) {
	t.Helper()

	before := len(logged.entries(t, "sign"))

	out, err := client.run(t, server, false, "echo", "ok")
	if err == nil {
		t.Fatalf("ssh to a server the policy does not name succeeded:\n%s", out)
	}

	if !strings.Contains(out, "Permission denied") {
		t.Fatalf("ssh failed for another reason: %v\n%s", err, out)
	}

	bind := last(t, logged, "session-bind")
	if bind["outcome"] != "allow" || bind["host"] != protocol.Fingerprint(server.hostKey.Marshal()) {
		t.Fatalf("the binding: %v", bind)
	}

	listing := last(t, logged, "identities")
	if listing["listed"] != float64(0) || listing["hidden"] != float64(1) {
		t.Fatalf("the listing after binding to the other host: %v", listing)
	}

	if after := len(logged.entries(t, "sign")); after != before {
		t.Fatalf("the client asked for %d signature(s) the policy cannot allow", after-before)
	}
}

// forwardedAgent: the login succeeds, and ssh-add on the far side, reaching
// the agent through the forwarded channel, is bound as forwarding and sees
// nothing.
func forwardedAgent(t *testing.T, client sshClient, server sshd, logged *records) {
	t.Helper()

	before := len(logged.entries(t, "sign"))

	// The far side runs the command through the login shell: the path, with
	// its space, is quoted for it.
	out, err := client.run(t, server, true, "'"+filepath.Join(client.root, "bin", "ssh-add")+"' -l")
	if err == nil {
		t.Fatalf("ssh-add over the forwarded agent listed the key:\n%s", out)
	}

	if !strings.Contains(out, "no identities") {
		t.Fatalf("ssh-add over the forwarded agent failed for another reason: %v\n%s", err, out)
	}

	bind := last(t, logged, "session-bind")
	if bind["outcome"] != "allow" || bind["forwarding"] != true {
		t.Fatalf("the forwarded connection's binding: %v", bind)
	}

	listing := last(t, logged, "identities")
	if listing["connection"] != bind["connection"] ||
		listing["listed"] != float64(0) || listing["hidden"] != float64(1) {
		t.Fatalf("the listing on the forwarded connection: %v", listing)
	}

	// The outer login signed once, allowed; the forwarded side asked for nothing.
	signs := logged.entries(t, "sign")
	if len(signs) != before+1 || signs[before]["outcome"] != "allow" {
		t.Fatalf("signatures during the forwarded session: %v", signs[before:])
	}
}
