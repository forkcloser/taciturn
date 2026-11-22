package cli_test

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/forkcloser/taciturn/internal/cli"
	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/keystore"
)

// The usage is printed where the caller looks for it: on stdout when it
// was asked for, on stderr with the reason when the command line is wrong.
func TestUsage(t *testing.T) {
	t.Parallel()

	const head = "taciturn: an ssh-agent for keys in the Secure Enclave"

	for name, c := range map[string]struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		"help":                {[]string{"help"}, 0, head, ""},
		"-h":                  {[]string{"-h"}, 0, head, ""},
		"no arguments":        {nil, 2, "", head},
		"unknown command":     {[]string{"frobnicate"}, 2, "", `unknown command "frobnicate"`},
		"key without command": {[]string{"key"}, 2, "", head},
		"unknown key command": {[]string{"key", "frobnicate"}, 2, "", `unknown key command "frobnicate"`},
	} {
		code, out, errOut := run(t, c.args...)
		if code != c.code || !strings.Contains(out, c.stdout) || !strings.Contains(errOut, c.stderr) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", name, code, out, errOut)
		}

		if (c.stdout == "") != (out == "") || (c.stderr == "") != (errOut == "") {
			t.Fatalf("%s: stdout %q, stderr %q", name, out, errOut)
		}

		// A wrong command line is told the usage as well as the reason.
		if c.code == 2 && !strings.Contains(errOut, "taciturn key create NAME") {
			t.Fatalf("%s: no usage on stderr: %q", name, errOut)
		}
	}
}

// Every command refuses what it cannot act on, before it acts: a missing
// name or a missing required flag is a failure that names it, a store that
// cannot be opened or a key that is not in it a failure of the store.
func TestCommandsRefuseBadArguments(t *testing.T) {
	t.Parallel()

	store, _ := seed(t, "bot")

	notAStore := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notAStore, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(
		knownHosts,
		[]byte("h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	// The agent's own files, should it get as far as making them.
	scratch := shortDir(t)

	// Each command with the arguments that make it complete, a name first
	// where it takes one.
	named := map[string][]string{
		"show":     nil,
		"allow":    {"-user", "git", "-host", "h", "-known-hosts", knownHosts},
		"disallow": {"-host", "h"},
		"peers":    nil,
		"sshsig":   {"-namespace", "git"},
		"delete":   {"-yes"},
		"rotate":   nil,
		"retire":   nil,
		"signers":  {"-principal", "bot@example"},
	}

	for command, flags := range named {
		code, out, errOut := run(t, "key", command)
		if code != 1 || !strings.Contains(errOut, "a key name is required") || out != "" {
			t.Fatalf("key %s without a name: exit %d: %q %q", command, code, out, errOut)
		}

		code, out, errOut = run(t, append([]string{"key", command, "bot", "-store", notAStore}, flags...)...)
		if code != 1 || !strings.Contains(errOut, "key store") || out != "" {
			t.Fatalf("key %s on what is not a store: exit %d: %q %q", command, code, out, errOut)
		}

		code, out, errOut = run(t, append([]string{"key", command, "absent", "-store", store}, flags...)...)
		if code != 1 || !strings.Contains(errOut, "key not found") || out != "" {
			t.Fatalf("key %s of an absent key: exit %d: %q %q", command, code, out, errOut)
		}
	}

	for name, c := range map[string]struct {
		args []string
		code int
		want string
	}{
		"create without a name":    {[]string{"key", "create"}, 1, "a key name is required"},
		"create with a bad use":    {[]string{"key", "create", "new", "-store", store, "-use", "sometimes", "-peers", "any"}, 1, "-use must be"},
		"create with a bad name":   {[]string{"key", "create", "-new", "-use", "locked"}, 1, "a key name is required"},
		"create with a bad peer":   {[]string{"key", "create", "new", "-store", store, "-use", "locked", "-peers", "any,path=relative"}, 1, "invalid peer entry"},
		"create with a taken name": {[]string{"key", "create", "b/d", "-store", store, "-use", "locked", "-peers", "any"}, 1, "invalid key record"},
		"create on no store":       {[]string{"key", "create", "new", "-store", notAStore, "-use", "locked", "-peers", "any"}, 1, "key store"},
		"agent on no store": {
			[]string{"agent", "-store", notAStore, "-socket", filepath.Join(scratch, "a.sock"), "-audit", filepath.Join(scratch, "audit.log")},
			1, "key store",
		},
		"agent, no socket directory": {
			[]string{"agent", "-store", store, "-socket", filepath.Join(notAStore, "a.sock"), "-audit", filepath.Join(scratch, "audit.log")},
			1, "creating",
		},
		"list on no store":        {[]string{"key", "list", "-store", notAStore}, 1, "key store"},
		"import on no store":      {[]string{"key", "import", "-store", notAStore}, 1, "key store"},
		"list in no such format":  {[]string{"key", "list", "-store", store, "-format", "yaml"}, 1, "format"},
		"show in no such format":  {[]string{"key", "show", "bot", "-store", store, "-format", "yaml"}, 1, "format"},
		"allow without a user":    {[]string{"key", "allow", "bot", "-store", store, "-host", "h", "-known-hosts", knownHosts}, 1, "missing argument"},
		"allow without a host":    {[]string{"key", "allow", "bot", "-store", store, "-user", "git", "-known-hosts", knownHosts}, 1, "missing argument"},
		"allow without the file":  {[]string{"key", "allow", "bot", "-store", store, "-user", "git", "-host", "h"}, 1, "missing argument"},
		"allow with no such file": {[]string{"key", "allow", "bot", "-store", store, "-user", "git", "-host", "h", "-known-hosts", notAStore + "x"}, 1, "known_hosts"},
		"disallow without a host": {[]string{"key", "disallow", "bot", "-store", store}, 1, "missing argument"},
		"sshsig without a name":   {[]string{"key", "sshsig", "bot", "-store", store}, 1, "missing argument"},
		"signers without one":     {[]string{"key", "signers", "bot", "-store", store}, 1, "missing argument"},
		"delete without -yes":     {[]string{"key", "delete", "bot", "-store", store}, 1, "deletion needs -yes"},
		"peers both ways":         {[]string{"key", "peers", "bot", "-store", store, "-add", "any", "-remove", "any"}, 1, "exclusive"},
	} {
		code, out, errOut := run(t, c.args...)
		if code != c.code || !strings.Contains(errOut, c.want) || out != "" {
			t.Fatalf("%s: exit %d: %q %q", name, code, out, errOut)
		}
	}

	// None of it touched the key.
	code, out, _ := run(t, "key", "list", "-store", store, "-format", "ssh")
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, " bot\n") {
		t.Fatalf("the store after the refusals: exit %d: %q", code, out)
	}
}

// show names a key's place in a rotation, and only where it has one.
func TestShowLineage(t *testing.T) {
	t.Parallel()

	dir, record := seed(t, "bot")

	code, out, _ := run(t, "key", "show", "bot", "-store", dir, "-format", "json")
	if code != 0 || strings.Contains(out, "predecessor") || strings.Contains(out, "successor") ||
		strings.Contains(out, "retired") {
		t.Fatalf("a key outside any rotation: exit %d: %s", code, out)
	}

	// The same key in a store of its own, as a rotation leaves one.
	dir = filepath.Join(t.TempDir(), "keys")

	store, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	before := "SHA256:" + strings.Repeat("A", 43)
	after := "SHA256:" + strings.Repeat("B", 43)
	retired := record.Created.Add(time.Hour)

	record.Predecessor, record.Successor, record.Retired = before, after, &retired
	if err = store.Create(record); err != nil {
		t.Fatal(err)
	}

	code, out, _ = run(t, "key", "show", record.Fingerprint, "-store", dir, "-format", "json")
	for _, want := range []string{
		`"predecessor": "` + before + `"`, `"successor": "` + after + `"`, `"retired": "2026-10-12T17:30:00Z"`,
		`"fingerprint": "` + record.Fingerprint + `"`, `"class": "after-first-unlock"`, `"created": "2026-10-12T16:30:00Z"`,
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("show lacks %s: exit %d: %s", want, code, out)
		}
	}
}

// A destination is a host and a user: allowing another user at a host adds
// one, allowing the same pair again replaces it, and disallowing a host
// removes every user there and no other host.
func TestDestinationsByHostAndUser(t *testing.T) {
	t.Parallel()

	const key = " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"

	store, _ := seed(t, "bot")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	if err := os.WriteFile(knownHosts, []byte("one.example"+key+"two.example"+key), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, pair := range [][2]string{
		{"git", "one.example"}, {"deploy", "one.example"}, {"git", "one.example"}, {"git", "two.example"},
	} {
		code, _, errOut := run(
			t,
			"key",
			"allow",
			"bot",
			"-store",
			store,
			"-user",
			pair[0],
			"-host",
			pair[1],
			"-known-hosts",
			knownHosts,
		)
		if code != 0 {
			t.Fatalf("allow %v: exit %d: %s", pair, code, errOut)
		}
	}

	destinations := func() string {
		t.Helper()

		code, out, _ := run(t, "key", "show", "bot", "-store", store, "-format", "json")
		if code != 0 {
			t.Fatalf("show: exit %d", code)
		}

		return out
	}

	shown := destinations()
	for want, times := range map[string]int{"git@one.example": 1, "deploy@one.example": 1, "git@two.example": 1, "host keys)": 3} {
		if strings.Count(shown, want) != times {
			t.Fatalf("%q %d times, want %d:\n%s", want, strings.Count(shown, want), times, shown)
		}
	}

	if code, _, errOut := run(t, "key", "disallow", "bot", "-store", store, "-host", "one.example"); code != 0 {
		t.Fatalf("disallow: exit %d: %s", code, errOut)
	}

	shown = destinations()
	if strings.Contains(shown, "one.example") || strings.Count(shown, "git@two.example") != 1 {
		t.Fatalf("after disallowing one host:\n%s", shown)
	}
}

// The usage says what each command takes, and a command refuses what the
// usage does not give it: -store is the key commands', the agent's and
// doctor's, and the audit log's path is the agent's and log's.
func TestUsageSaysWhatTheCommandsTake(t *testing.T) {
	t.Parallel()

	_, usage, _ := run(t, "help")

	for _, want := range []string{
		"taciturn agent [-audit FILE]",
		"taciturn log [-follow] [-json] [-key NAME] [-audit FILE]",
		"taciturn version | help",
		"taciturn key show NAME [-format console|json]",
		"its name or its SHA256: fingerprint",
		"The key commands, agent and doctor take -store DIR; agent, status and doctor\ntake -socket PATH.",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("the usage lacks %q:\n%s", want, usage)
		}
	}

	for _, command := range []string{"install", "uninstall", "status", "log"} {
		if code, _, _ := run(t, command, "-store", t.TempDir()); code != 2 {
			t.Fatalf("%s -store: exit %d", command, code)
		}
	}

	for _, command := range []string{"install", "uninstall", "log"} {
		if code, _, _ := run(t, command, "-socket", filepath.Join(t.TempDir(), "s")); code != 2 {
			t.Fatalf("%s -socket: exit %d", command, code)
		}
	}
}

// A key that exists is named to a key command by its name or by its
// fingerprint, and the command does the same with either.
func TestKeyCommandsTakeTheFingerprint(t *testing.T) {
	t.Parallel()

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(
		knownHosts,
		[]byte("h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	// In the order a key's life takes them; rotate needs the enclave and
	// is the hardware lane's.
	commands := [][]string{
		{"show"},
		{"allow", "-user", "git", "-host", "h", "-known-hosts", knownHosts},
		{"sshsig", "-namespace", "git"},
		{"peers", "-add", "path=/opt/ssh/bin/ssh"},
		{"signers", "-principal", "bot@example"},
		{"disallow", "-host", "h"},
		{"retire"},
		{"delete", "-yes"},
	}

	byName, _ := seed(t, "bot")
	byFingerprint, record := seed(t, "bot")

	for _, command := range commands {
		wantCode, wantOut, wantErr := run(
			t,
			append([]string{"key", command[0], "bot", "-store", byName}, command[1:]...)...,
		)
		code, out, errOut := run(
			t,
			append([]string{"key", command[0], record.Fingerprint, "-store", byFingerprint}, command[1:]...)...,
		)

		if wantCode != 0 || code != 0 {
			t.Fatalf(
				"key %s: exit %d by name (%s), %d by fingerprint (%s)",
				command[0],
				wantCode,
				wantErr,
				code,
				errOut,
			)
		}

		// The two stores hold two keys: what is printed differs by the key
		// alone, and by the instant of a retirement.
		if command[0] != "show" && command[0] != "signers" && command[0] != "retire" && command[0] != "delete" &&
			out != wantOut {
			t.Fatalf("key %s by fingerprint printed %q, by name %q", command[0], out, wantOut)
		}
	}

	for _, store := range []string{byName, byFingerprint} {
		if code, out, _ := run(t, "key", "list", "-store", store, "-format", "ssh"); code != 0 || out != "" {
			t.Fatalf("the store after the key's life: exit %d: %q", code, out)
		}
	}
}

// A flag a command does not have is a usage error: exit 2, the flag
// package's message and the command's flags on stderr, nothing on stdout,
// which is the command's output.
func TestAWrongFlagIsToldOnStderr(t *testing.T) {
	t.Parallel()

	for _, command := range [][]string{
		{"agent"},
		{"install"},
		{"uninstall"},
		{"status"},
		{"doctor"},
		{"log"},
		{"key", "list"},
		{"key", "import"},
		{"key", "create", "bot"},
		{"key", "show", "bot"},
		{"key", "allow", "bot"},
		{"key", "disallow", "bot"},
		{"key", "peers", "bot"},
		{"key", "sshsig", "bot"},
		{"key", "delete", "bot"},
		{"key", "rotate", "bot"},
		{"key", "retire", "bot"},
		{"key", "signers", "bot"},
	} {
		code, out, errOut := run(t, append(command, "-bogus")...)
		if code != 2 || out != "" || !strings.Contains(errOut, "flag provided but not defined: -bogus") {
			t.Fatalf("%v -bogus: exit %d, stdout %q, stderr %q", command, code, out, errOut)
		}
	}
}

// doctor reports each thing it checks on its own line and exits 1 when one
// is wrong. In the sandbox the enclave and the keychain are out of reach,
// which it says; the store and the socket are this test's.
func TestDoctor(t *testing.T) {
	t.Parallel()

	store, record := seed(t, "bot")
	dir := shortDir(t)

	absent := filepath.Join(dir, "absent")
	file := filepath.Join(dir, "file")
	open := filepath.Join(dir, "open.sock")
	private := filepath.Join(dir, "private.sock")

	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for path, mode := range map[string]os.FileMode{open: 0o644, private: 0o600} {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = listener.Close() })

		if err = os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	// What decides the skip is the enclave, not what doctor says of it.
	if enclave.Available() {
		t.Skip("the enclave answers: this process is outside the sandbox")
	}

	code, out, errOut := run(t, "doctor", "-store", store, "-socket", absent)

	for _, want := range []string{
		"FAIL secure enclave reachable from this process\n",
		"FAIL keychain access group : ",
		"ok   key store " + store + "\n",
		"ok   key store readable, 1 keys\n",
		"ok   0 keys still to move into the keychain",
		"FAIL key bot " + record.Fingerprint + ": ",
		"FAIL socket " + absent + ": absent\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor lacks %q:\n%s", want, out)
		}
	}

	if code != 1 || !strings.Contains(errOut, "doctor found problems: ") {
		t.Fatalf("doctor with problems: exit %d: %s", code, errOut)
	}

	for socket, want := range map[string]string{
		file:    "FAIL socket " + file + ": not a socket\n",
		open:    "FAIL socket " + open + ": mode 644, not 600\n",
		private: "ok   socket " + private + ": present, private\n",
	} {
		if _, out, _ = run(t, "doctor", "-store", store, "-socket", socket); !strings.Contains(out, want) {
			t.Fatalf("doctor lacks %q:\n%s", want, out)
		}
	}

	// A v0.1 blob file still in the store is a finding of its own.
	if err := os.WriteFile(filepath.Join(store, "leftover.blob"), []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(
		filepath.Join(store, "leftover.blob"),
		strings.TrimSuffix(recordPath(t, store), ".json")+".blob",
	); err != nil {
		t.Fatal(err)
	}

	if _, out, _ = run(
		t,
		"doctor",
		"-store",
		store,
		"-socket",
		absent,
	); !strings.Contains(
		out,
		"FAIL 1 keys still to move into the keychain",
	) {
		t.Fatalf("doctor with a blob file in the store:\n%s", out)
	}

	// A store that cannot be opened is one finding, and the keys are not
	// looked for in it.
	_, out, _ = run(t, "doctor", "-store", file, "-socket", absent)
	if !strings.Contains(out, "FAIL key store "+file+": ") || strings.Contains(out, "key store readable") {
		t.Fatalf("doctor on what is not a store:\n%s", out)
	}
}

// recordPath is the one record file of a store with one key.
func recordPath(t *testing.T, store string) string {
	t.Helper()

	records, err := filepath.Glob(filepath.Join(store, "*.json"))
	if err != nil || len(records) != 1 {
		t.Fatalf("the store's records: %v, %v", records, err)
	}

	return records[0]
}

// shortDir is a temporary directory short enough for a socket path.
func shortDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "tc") //nolint:usetesting // sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return dir
}

// The child's directory, and the audit log's path when it is not the one
// under it.
const (
	agentEnv      = "TACITURN_TEST_AGENT"
	agentAuditEnv = "TACITURN_TEST_AGENT_AUDIT"
)

// TestHelperAgent is the child process of TestAgentCommand: `taciturn
// agent` over the directory the environment names, until it is signalled;
// the command's exit code is the test's verdict, and so the child's.
func TestHelperAgent(t *testing.T) { //nolint:paralleltest // the one test of its process
	dir := os.Getenv(agentEnv)
	if dir == "" {
		t.Skip("not the child process")
	}

	audit := filepath.Join(dir, "logs", "audit.log")
	if elsewhere := os.Getenv(agentAuditEnv); elsewhere != "" {
		audit = elsewhere
	}

	code := cli.Run("test", []string{
		"agent",
		"-store", filepath.Join(dir, "keys"),
		"-socket", filepath.Join(dir, "run", "a.sock"),
		"-audit", audit,
	}, os.Stdout, os.Stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// An agent that cannot open its audit log does not serve: it says so and
// exits 1. In a child process, since one that served anyway would not
// return.
func TestAgentWithoutItsLogDoesNotServe(t *testing.T) {
	t.Parallel()

	dir := shortDir(t)

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperAgent$")

	child.Env = append(os.Environ(), agentEnv+"="+dir, agentAuditEnv+"="+filepath.Join(file, "audit.log"))
	child.WaitDelay = 5 * time.Second

	out, err := child.CombinedOutput()
	if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "taciturn: audit log") {
		t.Fatalf("the agent with no log to write: %v\n%s", err, out)
	}

	if _, err = os.Lstat(filepath.Join(dir, "run", "a.sock")); !os.IsNotExist(err) {
		t.Fatalf("a socket from an agent with no log: %v", err)
	}
}

// `taciturn agent` serves the store on the socket, private, says where on
// stderr, writes the audit log, private, and stops clean at a signal: exit
// 0, the socket gone, the stop on record.
func TestAgentCommand(t *testing.T) {
	t.Parallel()

	// The test asks the agent for its keys, and an agent that cannot
	// identify its peer closes the connection unanswered.
	if !haveFramework {
		t.Skip("built without Security.framework: the agent identifies no peer and answers none")
	}

	// An interrupt is a terminal's; SIGTERM is what launchd sends an agent
	// it unloads.
	for name, stop := range map[string]os.Signal{"interrupt": os.Interrupt, "terminate": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			agentServesUntil(t, stop)
		})
	}
}

// agentServesUntil runs `taciturn agent` as a child, holds it to what it
// serves and writes, and stops it with the signal.
func agentServesUntil(t *testing.T, stop os.Signal) {
	t.Helper()

	dir := shortDir(t)
	socket := filepath.Join(dir, "run", "a.sock")
	audit := filepath.Join(dir, "logs", "audit.log")

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	// A key whose policy allows something, so that it is listed.
	_, record := seed(t, "bot")
	record.Policy.Namespaces = []string{"git"}

	if err = store.Create(record); err != nil {
		t.Fatal(err)
	}

	// The child is given a minute: one that hangs is killed, its pipe
	// closes, and the test fails here instead of holding the run.
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperAgent$")

	child.Env = append(os.Environ(), agentEnv+"="+dir)
	child.WaitDelay = 5 * time.Second

	stderr, err := child.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err = child.Start(); err != nil {
		t.Fatal(err)
	}

	said, err := bufio.NewReader(stderr).ReadString('\n')
	if err != nil || said != "taciturn: serving "+socket+", audit log "+audit+"\n" {
		t.Fatalf("the agent's one line: %q, %v", said, err)
	}

	for path, mode := range map[string]os.FileMode{
		socket:               os.ModeSocket | 0o600,
		filepath.Dir(socket): os.ModeDir | 0o700,
		audit:                0o600,
		filepath.Dir(audit):  os.ModeDir | 0o700,
	} {
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode() != mode {
			t.Fatalf("%s: %v, %v", path, info, statErr)
		}
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	if err = conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}

	keys, err := sshagent.NewClient(conn).List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "bot" {
		t.Fatalf("the agent's keys: %v, %v", keys, err)
	}

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err = child.Process.Signal(stop); err != nil {
		t.Fatal(err)
	}

	if err = child.Wait(); err != nil {
		t.Fatalf("the agent after %s: %v", stop, err)
	}

	if _, err = os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("the socket after the stop: %v", err)
	}

	logged, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(logged)), "\n")
	for i, want := range []string{`"msg":"agent started"`, `"request":"identities"`, `"msg":"agent stopped"`} {
		if len(lines) != 3 || !strings.Contains(lines[i], want) {
			t.Fatalf("audit log line %d lacks %s:\n%s", i, want, logged)
		}
	}

	if !strings.Contains(lines[0], `"socket":"`+socket+`"`) ||
		!strings.Contains(lines[0], `"store":"`+store.Dir()+`"`) {
		t.Fatalf("the start on record: %s", lines[0])
	}
}
