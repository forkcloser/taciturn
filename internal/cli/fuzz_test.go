package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/keystore"
)

// Past the bound: a line of the audit log carries bytes a client chose (the
// user of a request, the path of its executable), and `taciturn log` prints
// it on a terminal. Whatever the line holds, the console view prints one
// line for it and nothing but printable characters, and -json prints it as
// it was written.
func FuzzLogLine(f *testing.F) {
	f.Add(
		[]byte(
			`{"time":"2026-10-12T16:00:01Z","msg":"request","outcome":"allow","request":"sign","name":"bot","user":"git","peer_path":"/usr/bin/ssh","rule":"peer allowed"}`,
		),
	)
	f.Add([]byte("{\"time\":\"2026-10-12T16:00:01Z\",\"msg\":\"request\",\"user\":\"a\\nb\"," +
		"\"peer_path\":\"/tmp/\\u001b[2Jx\",\"error\":\"\u202e\"}"))
	f.Add([]byte(`{"time":"2026-10-12T16:00:03Z","msg":"agent\tstarted"}`))
	f.Add([]byte("raw \x1b[31m line"))
	f.Add([]byte("raw \x9b31m line \xff"))
	f.Add([]byte(""))
	f.Add([]byte("{"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// One line: the log is read line by line, and a newline in the
		// input is two lines of it.
		line := bytes.ReplaceAll(data, []byte("\n"), []byte(" "))

		audit := filepath.Join(t.TempDir(), "audit.log")
		if err := os.WriteFile(audit, append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}

		code, out, errOut := run(t, "log", "-audit", audit)
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d: %q", code, errOut)
		}

		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Fatalf("one line in is one line out: %q", out)
		}

		if !utf8.ValidString(out) {
			t.Fatalf("bytes that are not text reached the console: %q", out)
		}

		for _, r := range strings.TrimSuffix(out, "\n") {
			if !strconv.IsPrint(r) {
				t.Fatalf("%q reached the console in %q", r, out)
			}
		}

		code, out, errOut = run(t, "log", "-audit", audit, "-json")
		if code != 0 || errOut != "" || out != string(line)+"\n" {
			t.Fatalf("-json is the line as written: exit %d: %q %q", code, out, errOut)
		}
	})
}

// Past the bound: a known_hosts file is text from elsewhere, and `key
// allow` reads it to decide which host keys a key may authenticate to.
// Whatever the file and the host name hold, the command ends, exit 0 or 1;
// when it allows, what it stored is host keys that parse, and when it
// refuses, the key's policy is untouched.
func FuzzKnownHosts(f *testing.F) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

	f.Add([]byte("example.com "+key+"\n"), "example.com")
	f.Add([]byte("*.example.com,!bad.example.com "+key+"\n"), "good.example.com")
	f.Add([]byte("[example.com]:2222 "+key+"\n@revoked * "+key+"\n"), "example.com")
	f.Add([]byte("|1|c2FsdA==|aGFzaA== "+key+"\n"), "example.com")
	f.Add([]byte("@cert-authority * "+key+"\nexample.com ssh-unknown AAAA\n"), "example.com")
	f.Add([]byte("example.com "+key), "")
	f.Add([]byte{0xff, 0, '\n', ' '}, "\x00")

	f.Fuzz(func(t *testing.T, file []byte, host string) {
		store, record := seed(t, "bot")

		knownHosts := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(knownHosts, file, 0o600); err != nil {
			t.Fatal(err)
		}

		code, _, errOut := run(
			t,
			"key",
			"allow",
			"bot",
			"-store",
			store,
			"-user",
			"git",
			"-host",
			host,
			"-known-hosts",
			knownHosts,
		)

		opened, err := keystore.Open(store)
		if err != nil {
			t.Fatal(err)
		}

		after, err := opened.Get(record.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}

		switch code {
		case 0:
			if len(after.Policy.Destinations) != 1 || after.Policy.Destinations[0].User != "git" ||
				len(after.Policy.Destinations[0].HostKeys) == 0 {
				t.Fatalf("allowed, and the policy holds %+v", after.Policy.Destinations)
			}

			for _, hostKey := range after.Policy.Destinations[0].HostKeys {
				if _, err = ssh.ParsePublicKey(hostKey); err != nil {
					t.Fatalf("a host key that is none was stored: %v", err)
				}
			}
		case 1:
			if len(after.Policy.Destinations) != 0 {
				t.Fatalf("refused (%s), and the policy holds %+v", errOut, after.Policy.Destinations)
			}
		default:
			t.Fatalf("exit %d: %s", code, errOut)
		}
	})
}
