package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/agent"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/peer"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The audit log is the agent's record of what it was asked and what it
// answered (the package comment: every request writes one record). These
// tests read it as the log command does, a line of JSON per record, from an
// agent logging to memory, and speak to the socket in the protocol's own
// frames so that a malformed request is one of the requests.

// journal collects what the agent logs.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.buf.Write(p)
}

// entry is one logged line.
type entry map[string]any

func (e entry) text(key string) string {
	value, ok := e[key].(string)
	if !ok {
		return ""
	}

	return value
}

// entries is every line logged so far with the message given.
func (j *journal) entries(t *testing.T, message string) []entry {
	t.Helper()

	j.mu.Lock()
	defer j.mu.Unlock()

	var out []entry

	for line := range bytes.SplitSeq(bytes.TrimSpace(j.buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}

		var one entry
		if err := json.Unmarshal(line, &one); err != nil {
			t.Fatalf("the log holds a line that is not JSON: %q", line)
		}

		if one.text("msg") == message {
			out = append(out, one)
		}
	}

	return out
}

// requests is every audit record so far.
func (j *journal) requests(t *testing.T) []entry {
	t.Helper()

	return j.entries(t, "request")
}

// last is the newest audit record, which must be the count-th: a request
// that left none, or two, fails here.
func (j *journal) last(t *testing.T, count int) entry {
	t.Helper()

	records := j.requests(t)
	if len(records) != count {
		t.Fatalf("%d audit records after %d requests", len(records), count)
	}

	return records[count-1]
}

// logged is a running agent, on its defaults, that logs to a journal.
func logged(t *testing.T) (*rig, *journal) {
	t.Helper()

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	log := &journal{}
	socket := filepath.Join(dir, "a.sock")

	server, err := agent.Listen(socket, agent.Config{Store: store, Logger: slog.New(slog.NewJSONHandler(log, nil))})
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

		_ = server.Close()
	})

	return &rig{store: store, server: server, socket: socket}, log
}

// wire is a connection to the agent in the protocol's own frames.
type wire struct {
	conn net.Conn
}

func (r *rig) wire(t *testing.T) wire {
	t.Helper()

	conn, err := net.Dial("unix", r.socket)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	return wire{conn}
}

// ask sends one request and returns the answer's type.
func (w wire) ask(t *testing.T, kind protocol.Type, payload []byte) protocol.Type {
	t.Helper()

	if _, err := (protocol.Message{Type: kind, Payload: payload}).WriteTo(w.conn); err != nil {
		t.Fatal(err)
	}

	if err := w.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	answer, err := protocol.ReadMessage(w.conn)
	if err != nil {
		t.Fatalf("no answer to %s: %v", kind, err)
	}

	return answer.Type
}

func (w wire) extension(t *testing.T, name string, contents []byte) protocol.Type {
	t.Helper()

	return w.ask(t, protocol.TypeExtension, append(ssh.Marshal(struct{ Name string }{name}), contents...))
}

func (w wire) sign(t *testing.T, keyBlob, data []byte) protocol.Type {
	t.Helper()

	return w.ask(t, protocol.TypeSignRequest, ssh.Marshal(struct {
		Key   []byte
		Data  []byte
		Flags uint32
	}{keyBlob, data, 0}))
}

// expect holds one audit record to the fields named.
func expect(t *testing.T, record entry, want map[string]any) {
	t.Helper()

	for key, value := range want {
		got := record[key]

		// JSON numbers decode as float64.
		if number, ok := value.(int); ok {
			value = float64(number)
		}

		if got != value {
			t.Fatalf("audit record %v: %s is %v, want %v", record, key, got, value)
		}
	}
}

// Every request leaves exactly one record, allowed or refused, malformed or
// not, saying what was asked, of which key, on what binding, and the rule
// that decided; and every record says who asked.
func TestEveryRequestLeavesOneRecord(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r, log := logged(t)
	h := newHost(t)
	other := newHost(t)

	record := botKey(t, "bot", github(h))
	if err := r.store.Create(record); err != nil {
		t.Fatal(err)
	}

	stranger := botKey(t, "stranger", github(h))
	bound := "auth " + protocol.Fingerprint(h.blob)
	conn := r.wire(t)
	count := 0

	step := func(answer, wantAnswer protocol.Type, want map[string]any) {
		t.Helper()

		count++

		if answer != wantAnswer {
			t.Fatalf("request %d: answer %s, want %s", count, answer, wantAnswer)
		}

		expect(t, log.last(t, count), want)
	}

	step(conn.ask(t, protocol.TypeRequestIdentities, nil), protocol.TypeIdentitiesAnswer,
		map[string]any{"outcome": "allow", "request": "identities", "listed": 1, "hidden": 0, "bound": "none"})

	step(conn.extension(t, protocol.ExtensionQuery, nil), protocol.TypeExtensionResponse,
		map[string]any{"outcome": "allow", "request": "extension", "extension": "query"})

	step(conn.extension(t, "frobnicate@example", nil), protocol.TypeFailure, map[string]any{
		"outcome":   "refuse",
		"request":   "extension",
		"extension": "frobnicate@example",
		"rule":      "extension not supported",
	})

	step(conn.ask(t, protocol.TypeExtension, []byte{0, 0}), protocol.TypeFailure,
		map[string]any{"outcome": "refuse", "request": "extension", "rule": "malformed extension"})

	step(conn.ask(t, protocol.TypeRemoveAllIdentities, nil), protocol.TypeFailure,
		map[string]any{"outcome": "refuse", "request": "remove-all-identities", "rule": "request type not served"})

	step(conn.ask(t, protocol.TypeSignRequest, []byte{0}), protocol.TypeFailure,
		map[string]any{"outcome": "refuse", "request": "sign", "rule": "malformed sign request"})

	step(conn.sign(t, stranger.PublicKey, sshsig("git")), protocol.TypeFailure,
		map[string]any{"outcome": "refuse", "request": "sign", "rule": "key unknown", "key": stranger.Fingerprint})

	step(conn.sign(t, record.PublicKey, sshsig("file")), protocol.TypeFailure, map[string]any{
		"outcome": "refuse", "request": "sign", "rule": policy.RuleNamespace,
		"key": record.Fingerprint, "name": "bot", "data": "sshsig", "namespace": "file", "bound": "none",
	})

	step(conn.sign(t, record.PublicKey, []byte("neither shape")), protocol.TypeFailure,
		map[string]any{"outcome": "refuse", "request": "sign", "rule": policy.RuleNotSSHSig, "data": "other"})

	step(
		conn.extension(t, protocol.ExtensionSessionBind, h.bind(t, sessionID(), false)),
		protocol.TypeSuccess,
		map[string]any{
			"outcome": "allow", "request": "session-bind", "rule": "host key proof verified",
			"host": protocol.Fingerprint(h.blob), "forwarding": false, "bound": bound,
		},
	)

	step(
		conn.extension(t, protocol.ExtensionSessionBind, h.bind(t, sessionID(), false)),
		protocol.TypeSuccess,
		map[string]any{
			"outcome": "allow",
			"request": "session-bind",
			"rule":    "binding already recorded",
			"bound":   bound,
		},
	)

	step(conn.ask(t, protocol.TypeRequestIdentities, nil), protocol.TypeIdentitiesAnswer,
		map[string]any{"outcome": "allow", "request": "identities", "listed": 1, "hidden": 0, "bound": bound})

	step(
		conn.sign(t, record.PublicKey, userauth(sessionID(), "root", record.PublicKey)),
		protocol.TypeFailure,
		map[string]any{
			"outcome": "refuse", "request": "sign", "rule": policy.RuleUser,
			"key": record.Fingerprint, "name": "bot", "data": "userauth", "user": "root", "bound": bound,
		},
	)

	step(
		conn.extension(t, protocol.ExtensionSessionBind, other.bind(t, sessionID(), false)),
		protocol.TypeFailure,
		map[string]any{
			"outcome": "refuse", "request": "session-bind", "rule": "connection already bound",
			"host": protocol.Fingerprint(other.blob), "bound": "refused",
		},
	)

	step(conn.ask(t, protocol.TypeRequestIdentities, nil), protocol.TypeIdentitiesAnswer,
		map[string]any{"outcome": "allow", "request": "identities", "listed": 0, "hidden": 1, "bound": "refused"})

	// Who asked is on every record: this process, by pid, path and
	// signature. The path is the executable's, or, for the main executable
	// of a bundle, which is how the hardware lane runs this test, the
	// bundle's.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	own := evaluated(t, executable)

	first, numbered := log.last(t, count)["connection"].(float64)
	if !numbered {
		t.Fatalf("a record without its connection: %v", log.last(t, count))
	}

	for _, one := range log.requests(t) {
		expect(t, one, map[string]any{"peer_pid": os.Getpid(), "peer_signed": true, "connection": first})

		got, _ := filepath.EvalSymlinks(one.text("peer_path"))
		if got != own && got+"/Contents/MacOS/"+filepath.Base(own) != own {
			t.Fatalf("peer_path %q, want %q or its bundle", one.text("peer_path"), own)
		}

		if one.text("peer_identifier") == "" || one.text("peer_cdhash") == "" {
			t.Fatalf("who asked: %v", one)
		}
	}

	// The next connection is the next number.
	count++

	r.wire(t).ask(t, protocol.TypeRequestIdentities, nil)

	if next := log.last(t, count)["connection"]; next != first+1 {
		t.Fatalf("connection %v after connection %v", next, first)
	}
}

func evaluated(t *testing.T, path string) string {
	t.Helper()

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}

	return resolved
}

// The bindings that are refused each say why, and one for forwarding says
// so and hides every key from then on.
func TestBindingsAreRecorded(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r, log := logged(t)
	h := newHost(t)
	forger := newHost(t)

	if err := r.store.Create(botKey(t, "bot", github(h))); err != nil {
		t.Fatal(err)
	}

	// The host key of one server over the proof of another.
	forged := ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{h.blob, sessionID(), signature(t, forger, sessionID()), false})

	count := 0

	for _, c := range []struct {
		contents []byte
		answer   protocol.Type
		want     map[string]any
	}{
		{[]byte{0}, protocol.TypeFailure, map[string]any{"outcome": "refuse", "rule": "malformed session-bind", "host": ""}},
		{forged, protocol.TypeFailure, map[string]any{
			"outcome": "refuse", "rule": "host key signature does not verify", "host": protocol.Fingerprint(h.blob),
		}},
		{h.bind(t, sessionID(), true), protocol.TypeSuccess, map[string]any{
			"outcome": "allow", "rule": "host key proof verified", "forwarding": true,
			"bound": "forwarding " + protocol.Fingerprint(h.blob),
		}},
	} {
		conn := r.wire(t)
		count++

		if answer := conn.extension(t, protocol.ExtensionSessionBind, c.contents); answer != c.answer {
			t.Fatalf("bind %d: answer %s", count, answer)
		}

		record := log.last(t, count)
		expect(t, record, map[string]any{"request": "session-bind"})
		expect(t, record, c.want)

		// A connection whose binding was refused, or is for forwarding,
		// lists nothing and says a key was hidden.
		count++

		conn.ask(t, protocol.TypeRequestIdentities, nil)
		expect(t, log.last(t, count), map[string]any{"request": "identities", "listed": 0, "hidden": 1})
	}

	// After a refusal, the next binding is refused for it.
	conn := r.wire(t)
	conn.extension(t, protocol.ExtensionSessionBind, []byte{0})
	conn.extension(t, protocol.ExtensionSessionBind, h.bind(t, sessionID(), false))
	expect(t, log.last(t, count+2), map[string]any{
		"outcome": "refuse", "request": "session-bind", "rule": "an earlier binding was refused",
	})
}

// signature is a host's proof over a session identifier, as the wire
// carries it.
func signature(t *testing.T, h host, sid []byte) []byte {
	t.Helper()

	made, err := h.signer.Sign(nil, sid)
	if err != nil {
		t.Fatal(err)
	}

	return ssh.Marshal(made)
}

// A key that is retired, or hidden from the binding, is passed over: the
// keys after it in the store are still listed.
func TestListingPassesOverWhatItLeavesOut(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r, log := logged(t)
	h := newHost(t)
	elsewhere := newHost(t)

	// The store lists oldest first and these are of one instant, so by name.
	retired := botKey(t, "a-retired", github(h))
	when := time.Now()
	retired.Retired = &when

	for _, record := range []keystore.Record{
		retired,
		botKey(t, "b-elsewhere", github(elsewhere)),
		botKey(t, "c-here", github(h)),
	} {
		if err := r.store.Create(record); err != nil {
			t.Fatal(err)
		}
	}

	client := r.client(t)

	if _, err := client.Extension(protocol.ExtensionSessionBind, h.bind(t, sessionID(), false)); err != nil {
		t.Fatal(err)
	}

	keys, err := client.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "c-here" {
		t.Fatalf("listed %v, %v", keys, err)
	}

	expect(t, log.last(t, 2), map[string]any{"request": "identities", "listed": 1, "hidden": 1})
}

// A peer entry that is a code requirement admits the peer that satisfies
// it and no other, wherever it stands in the list and whatever stands
// beside it.
func TestPeerRequirements(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	own := `identifier "` + ownIdentifier(t) + `"`
	apple := `anchor apple and identifier "com.apple.ssh"`

	for name, c := range map[string]struct {
		peers []string
		rule  string
	}{
		"the requirement it satisfies":      {[]string{own}, policy.RuleAllowedSSHSig},
		"a requirement it does not satisfy": {[]string{apple}, policy.RulePeer},
		"after a path that is not its own":  {[]string{policy.PeerPathPrefix + "/usr/bin/ssh", own}, policy.RuleAllowedSSHSig},
		"after one it does not satisfy":     {[]string{apple, own}, policy.RuleAllowedSSHSig},
		"after one that is no requirement":  {[]string{"not a requirement (((", own}, policy.RuleAllowedSSHSig},
		"only one that is no requirement":   {[]string{"not a requirement ((("}, policy.RulePeer},
		"no entry at all":                   {nil, policy.RulePeer},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r, log := logged(t)
			pol := policy.Policy{Namespaces: []string{"git"}, Peers: c.peers}
			record := botKey(t, "bot", pol)

			if err := r.store.Create(record); err != nil {
				t.Fatal(err)
			}

			// Allowed by the policy, the request then fails at the
			// enclave, which holds no such key: the rule is the verdict.
			if answer := r.wire(t).sign(t, record.PublicKey, sshsig("git")); answer != protocol.TypeFailure {
				t.Fatalf("answer %s", answer)
			}

			expect(t, log.last(t, 1), map[string]any{"outcome": "refuse", "request": "sign", "rule": c.rule})

			if _, failed := log.last(t, 1)["error"]; failed != (c.rule == policy.RuleAllowedSSHSig) {
				t.Fatalf("the enclave was asked: %v, rule %s", failed, c.rule)
			}

			unread := len(log.entries(t, "requirement not evaluated"))
			if want := count(c.peers, "not a requirement ((("); unread != want {
				t.Fatalf("%d entries reported as not evaluated, want %d", unread, want)
			}
		})
	}
}

func count(entries []string, one string) int {
	total := 0

	for _, entry := range entries {
		if entry == one {
			total++
		}
	}

	return total
}

// ownIdentifier is this test binary's code-signing identifier.
func ownIdentifier(t *testing.T) string {
	t.Helper()

	path := filepath.Join(shortDir(t), "p")

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
	if err != nil {
		t.Fatal(err)
	}

	defer identity.Close()

	return identity.Identifier
}

// A store that cannot be read refuses the listing and the signature, each
// on record with the store's error: nothing is served from half a store.
func TestUnreadableStoreIsRecorded(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r, log := logged(t)

	record := botKey(t, "bot", policy.Policy{Namespaces: []string{"git"}, Peers: []string{policy.PeerAny}})
	if err := r.store.Create(record); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(r.store.Dir(), "garbage.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := r.wire(t)

	if answer := conn.ask(t, protocol.TypeRequestIdentities, nil); answer != protocol.TypeFailure {
		t.Fatalf("a listing from an unreadable store: %s", answer)
	}

	listing := log.last(t, 1)
	expect(t, listing, map[string]any{"outcome": "refuse", "request": "identities", "rule": "key store unreadable"})

	if !strings.Contains(listing.text("error"), "corrupt key store") {
		t.Fatalf("the listing's record: %v", listing)
	}

	if answer := conn.sign(t, record.PublicKey, sshsig("git")); answer != protocol.TypeFailure {
		t.Fatalf("a signature from an unreadable store: %s", answer)
	}

	signing := log.last(t, 2)
	expect(t, signing, map[string]any{"outcome": "refuse", "request": "sign", "key": record.Fingerprint})

	if !strings.Contains(signing.text("rule"), "key store unreadable") {
		t.Fatalf("the signature's record: %v", signing)
	}
}

// Without a configuration the defaults serve: a connection is answered,
// not closed at once by a zero deadline.
func TestDefaultsServe(t *testing.T) {
	t.Parallel()
	requirePeerIdentity(t)

	r, _ := logged(t)

	conn := r.wire(t)
	for range 2 {
		if answer := conn.ask(t, protocol.TypeRequestIdentities, nil); answer != protocol.TypeIdentitiesAnswer {
			t.Fatalf("answer %s", answer)
		}
	}
}
