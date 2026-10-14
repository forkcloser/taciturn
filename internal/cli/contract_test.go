// The contract of package cli, through Run alone: the exit codes (0 done,
// 1 refused or failed, 2 usage), the key commands over a store of the
// test's making, the allowed-signers line, the known_hosts reading, the
// audit log rendering. What needs the enclave (create, rotate) or launchd
// (install, status) is exercised on the machine, not here: in the sandbox
// those commands fail at the enclave, which the tests assert.
package cli_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forkcloser/taciturn/internal/cli"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()

	var out, errOut bytes.Buffer

	code = cli.Run("test", args, &out, &errOut)

	return code, out.String(), errOut.String()
}

// seed puts a key in a fresh store without the enclave: a real P-256
// public key and a blob that is not the enclave's.
func seed(t *testing.T, name string) (string, keystore.Record) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "keys")

	store, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	public, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	record := keystore.Record{
		Fingerprint: protocol.Fingerprint(public),
		Name:        name,
		PublicKey:   public,
		Class:       keystore.ClassAfterFirstUnlock,
		Created:     time.Date(2026, time.October, 12, 16, 30, 0, 0, time.UTC),
		Policy:      policy.Policy{Peers: []string{policy.PeerAny}},
	}

	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}

	return dir, record
}

func TestExitCodes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		args []string
		code int
	}{
		"no arguments":        {nil, 2},
		"unknown command":     {[]string{"frobnicate"}, 2},
		"help":                {[]string{"help"}, 0},
		"version":             {[]string{"version"}, 0},
		"key without command": {[]string{"key"}, 2},
		"key unknown":         {[]string{"key", "frobnicate"}, 2},
		"key create no name":  {[]string{"key", "create"}, 1},
		"key create bad flag": {[]string{"key", "create", "bot", "-bogus"}, 2},
		"key delete no yes":   {[]string{"key", "delete", "bot", "-store", t.TempDir()}, 1},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if code, _, _ := run(t, c.args...); code != c.code {
				t.Fatalf("%v: exit %d, want %d", c.args, code, c.code)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()

	_, out, _ := run(t, "version")
	if out != "taciturn test\n" {
		t.Fatalf("%q", out)
	}
}

func TestListAndShow(t *testing.T) {
	t.Parallel()

	store, record := seed(t, "bot")

	code, out, _ := run(t, "key", "list", "-store", store, "-format", "ssh")
	if code != 0 ||
		out != protocol.AlgorithmECDSAP256+" "+base64.StdEncoding.EncodeToString(record.PublicKey)+" bot\n" {
		t.Fatalf("exit %d: %q", code, out)
	}

	code, out, _ = run(t, "key", "list", "-store", store, "-format", "json")
	if code != 0 || !strings.Contains(out, record.Fingerprint) || !strings.Contains(out, "after-first-unlock") {
		t.Fatalf("exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "show", "bot", "-store", store)
	if code != 0 || !strings.Contains(out, record.Fingerprint) {
		t.Fatalf("exit %d: %s", code, out)
	}

	code, _, errOut := run(t, "key", "show", "nobody", "-store", store)
	if code != 1 || !strings.Contains(errOut, "not found") {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	code, out, _ = run(t, "key", "list", "-store", filepath.Join(t.TempDir(), "empty"), "-format", "ssh")
	if code != 0 || out != "" {
		t.Fatalf("empty store: exit %d: %q", code, out)
	}
}

func TestPolicyEdits(t *testing.T) {
	t.Parallel()

	store, _ := seed(t, "bot")

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	hostLine := "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
	otherLine := "[other.example]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"

	if err := os.WriteFile(knownHosts, []byte("# comment\n"+hostLine+otherLine), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := run(
		t,
		"key",
		"allow",
		"bot",
		"-store",
		store,
		"-user",
		"git",
		"-host",
		"github.com",
		"-known-hosts",
		knownHosts,
	)
	if code != 0 || !strings.Contains(out, "github.com as git (1 host keys)") {
		t.Fatalf("allow: exit %d: %s %s", code, out, errOut)
	}

	code, _, errOut = run(
		t,
		"key",
		"allow",
		"bot",
		"-store",
		store,
		"-user",
		"git",
		"-host",
		"nowhere.example",
		"-known-hosts",
		knownHosts,
	)
	if code != 1 || !strings.Contains(errOut, "no host keys") {
		t.Fatalf("allow unknown host: exit %d: %s", code, errOut)
	}

	code, _, errOut = run(t, "key", "allow", "bot", "-store", store, "-user", "git")
	if code != 1 || !strings.Contains(errOut, "missing argument") {
		t.Fatalf("allow without host: exit %d: %s", code, errOut)
	}

	code, out, _ = run(t, "key", "sshsig", "bot", "-store", store, "-namespace", "git")
	if code != 0 || !strings.Contains(out, "signs in: git") {
		t.Fatalf("sshsig: exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "show", "bot", "-store", store, "-format", "json")
	if code != 0 || !strings.Contains(out, "git@github.com (1 host keys)") || !strings.Contains(out, `"git"`) {
		t.Fatalf("show after edits: %s", out)
	}

	code, out, _ = run(t, "key", "sshsig", "bot", "-store", store, "-namespace", "git", "-remove")
	if code != 0 || strings.Contains(out, "git") {
		t.Fatalf("sshsig remove: exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "disallow", "bot", "-store", store, "-host", "github.com")
	if code != 0 || !strings.Contains(out, "no longer") {
		t.Fatalf("disallow: exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "show", "bot", "-store", store, "-format", "json")
	if code != 0 || strings.Contains(out, "github.com") {
		t.Fatalf("show after disallow: %s", out)
	}
}

func TestSignersRetireDelete(t *testing.T) {
	t.Parallel()

	store, record := seed(t, "bot")

	code, out, _ := run(t, "key", "signers", "bot", "-store", store, "-principal", "bot@example.com")
	want := `bot@example.com namespaces="git",valid-after="20261012163000Z" ` + protocol.AlgorithmECDSAP256 + " " + base64.StdEncoding.EncodeToString(
		record.PublicKey,
	) + "\n"

	if code != 0 || out != want {
		t.Fatalf("signers: exit %d:\n%s\nwant\n%s", code, out, want)
	}

	code, _, _ = run(t, "key", "retire", "bot", "-store", store)
	if code != 0 {
		t.Fatalf("retire: exit %d", code)
	}

	code, out, _ = run(t, "key", "signers", "bot", "-store", store, "-principal", "bot@example.com")
	if code != 0 || !strings.Contains(out, `",valid-before="`) {
		t.Fatalf("signers after retire: %s", out)
	}

	code, _, errOut := run(t, "key", "retire", "bot", "-store", store)
	if code != 1 || !strings.Contains(errOut, "retired") {
		t.Fatalf("retire twice: exit %d: %s", code, errOut)
	}

	code, out, _ = run(t, "key", "list", "-store", store, "-format", "ssh")
	if code != 0 || out != "" {
		t.Fatalf("a retired key is not listed for ssh: %q", out)
	}

	code, _, errOut = run(t, "key", "rotate", "bot", "-store", store)
	if code != 1 || !strings.Contains(errOut, "retired") {
		t.Fatalf("rotate a retired key: exit %d: %s", code, errOut)
	}

	code, out, _ = run(t, "key", "delete", "bot", "-store", store, "-yes")
	if code != 0 || !strings.Contains(out, "deleted bot") {
		t.Fatalf("delete: exit %d: %s", code, out)
	}

	code, _, _ = run(t, "key", "show", "bot", "-store", store)
	if code != 1 {
		t.Fatalf("show after delete: exit %d", code)
	}
}

// Creating a key needs the enclave; where it cannot be reached the command
// says so and refuses, leaving the store untouched.
func TestCreateWithoutTheEnclave(t *testing.T) {
	t.Parallel()

	store := filepath.Join(t.TempDir(), "keys")

	code, _, errOut := run(t, "key", "create", "bot", "-store", store, "-use", "locked")
	if code == 0 {
		t.Skip("the enclave answered: this process is outside the sandbox")
	}

	if !strings.Contains(errOut, "enclave") {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	code, out, _ := run(t, "key", "list", "-store", store, "-format", "ssh")
	if code != 0 || out != "" {
		t.Fatalf("store after a refused create: %q", out)
	}

	code, _, errOut = run(t, "key", "create", "bot", "-store", store)
	if code != 1 || !strings.Contains(errOut, "-use") {
		t.Fatalf("create without -use: exit %d: %s", code, errOut)
	}
}

func TestLogRendering(t *testing.T) {
	t.Parallel()

	audit := filepath.Join(t.TempDir(), "audit.log")
	lines := `{"time":"2026-10-12T16:00:00Z","level":"INFO","msg":"agent started","socket":"/s"}
{"time":"2026-10-12T16:00:01Z","level":"INFO","msg":"request","outcome":"allow","request":"sign","name":"bot","rule":"SSHSIG within an allowed namespace","data":"sshsig","peer_path":"/usr/bin/ssh-keygen"}
{"time":"2026-10-12T16:00:02Z","level":"INFO","msg":"request","outcome":"refuse","request":"sign","name":"other","rule":"peer not allowed","data":"userauth","user":"git","peer_path":"/tmp/x"}
not json at all
`

	if err := os.WriteFile(audit, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, _ := run(t, "log", "-audit", audit)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	for _, want := range []string{
		"2026-10-12T16:00:00Z agent started",
		"2026-10-12T16:00:01Z allow sign bot sshsig /usr/bin/ssh-keygen - SSHSIG within an allowed namespace",
		"2026-10-12T16:00:02Z refuse sign other userauth git /tmp/x - peer not allowed",
		"not json at all",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = run(t, "log", "-audit", audit, "-key", "bot", "-json")
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, `"name":"bot"`) {
		t.Fatalf("filtered json: exit %d:\n%s", code, out)
	}

	code, _, errOut := run(t, "log", "-audit", filepath.Join(t.TempDir(), "none"))
	if code != 1 || !strings.Contains(errOut, "audit log") {
		t.Fatalf("missing log: exit %d: %s", code, errOut)
	}
}

// The peers of a key are edited one entry at a time, each checked as the
// agent will read it: a relative or malformed path glob and a requirement
// the framework does not parse are refused before anything is stored.
func TestPeers(t *testing.T) {
	t.Parallel()

	store, _ := seed(t, "deploy")
	requirement := `anchor apple and identifier "com.apple.ssh"`

	code, out, errOut := run(t, "key", "peers", "deploy", "-store", store, "-add", requirement)
	if code != 0 && strings.Contains(errOut, "unavailable") {
		t.Skip("built without the framework: requirements cannot be checked here")
	}

	if code != 0 || !strings.Contains(out, "2 peers") || !strings.Contains(out, requirement) {
		t.Fatalf("add requirement: exit %d: %s %s", code, out, errOut)
	}

	code, out, _ = run(t, "key", "peers", "deploy", "-store", store, "-add", "path=/opt/ssh/*/bin/ssh")
	if code != 0 || !strings.Contains(out, "3 peers") {
		t.Fatalf("add path: exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "peers", "deploy", "-store", store, "-add", "path=/opt/ssh/*/bin/ssh")
	if code != 0 || !strings.Contains(out, "3 peers") {
		t.Fatalf("add path twice: exit %d: %s", code, out)
	}

	for _, bad := range []string{"path=relative/ssh", "path=/opt/[", `anchor apple and identifier`, "anchor \xff apple"} {
		code, _, errOut = run(t, "key", "peers", "deploy", "-store", store, "-add", bad)
		if code != 1 || !strings.Contains(errOut, "invalid peer entry") {
			t.Fatalf("add %q: exit %d: %s", bad, code, errOut)
		}
	}

	code, _, errOut = run(t, "key", "peers", "deploy", "-store", store, "-add", "any", "-remove", "any")
	if code != 1 || !strings.Contains(errOut, "exclusive") {
		t.Fatalf("add and remove: exit %d: %s", code, errOut)
	}

	code, out, _ = run(t, "key", "peers", "deploy", "-store", store, "-remove", "any")
	if code != 0 || !strings.Contains(out, "2 peers") || strings.Contains(out, "  any\n") {
		t.Fatalf("remove: exit %d: %s", code, out)
	}

	code, out, _ = run(t, "key", "show", "deploy", "-store", store, "-format", "json")
	if code != 0 || !strings.Contains(out, "/opt/ssh/*/bin/ssh") || !strings.Contains(out, "com.apple.ssh") {
		t.Fatalf("show after peers: %s", out)
	}

	code, out, _ = run(t, "key", "peers", "deploy", "-store", store)
	if code != 0 || !strings.Contains(out, "2 peers") {
		t.Fatalf("peers alone lists: exit %d: %s", code, out)
	}

	code, _, errOut = run(t, "key", "create", "bot2", "-store", store, "-use", "locked", "-peers", "any,")
	if code != 1 || !strings.Contains(errOut, "invalid peer entry") {
		t.Fatalf("create with a bad peer: exit %d: %s", code, errOut)
	}
}

// `key import` moves nothing where nothing is pending, and where a v0.1
// blob is pending it needs the keychain: in a process without it the
// command fails and the blob stays, which is the safe side.
func TestImport(t *testing.T) {
	t.Parallel()

	store, record := seed(t, "bot")

	code, out, _ := run(t, "key", "import", "-store", store)
	if code != 0 || !strings.Contains(out, "nothing to import") {
		t.Fatalf("import with nothing pending: exit %d: %s", code, out)
	}

	blob := filepath.Join(
		store,
		strings.NewReplacer("/", "_", "+", "-").Replace(record.Fingerprint[len("SHA256:"):])+".blob",
	)
	if err := os.WriteFile(blob, bytes.Repeat([]byte{1}, 324), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := run(t, "key", "import", "-store", store)
	if code == 0 {
		t.Skip("the keychain answered: this process is in the signed bundle")
	}

	if !strings.Contains(errOut, record.Fingerprint) {
		t.Fatalf("import without the keychain: exit %d: %s", code, errOut)
	}

	if _, err := os.Stat(blob); err != nil {
		t.Fatalf("the blob did not stay after a failed import: %v", err)
	}

	code, out, _ = run(t, "doctor", "-store", store, "-socket", filepath.Join(t.TempDir(), "none"))
	if code == 0 || !strings.Contains(out, "1 keys still to move into the keychain") {
		t.Fatalf("doctor with a pending blob: exit %d: %s", code, out)
	}
}
