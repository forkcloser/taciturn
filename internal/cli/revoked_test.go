package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/forkcloser/taciturn/internal/keystore"
)

// hostKey makes a host key: as a known_hosts line carries it, and as the
// policy stores it.
func hostKey(t *testing.T) (text string, wire []byte) {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), key.Marshal()
}

// hostCertificate makes a host key and a certificate of it, each as a
// known_hosts line carries it.
func hostCertificate(t *testing.T) (key, certificate string) {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	certified, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	authority, err := ssh.NewSignerFromSigner(private)
	if err != nil {
		t.Fatal(err)
	}

	signed := &ssh.Certificate{
		Key:             certified,
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"certified.example"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err = signed.SignCert(rand.Reader, authority); err != nil {
		t.Fatal(err)
	}

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(certified))),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signed)))
}

// A key the file revokes for the host is left out of the destination, as
// ssh refuses a server that presents it: wherever the @revoked line stands,
// and however it names the host, by name, hashed, with a port, or by a
// pattern, and by a certificate of the key as by the key. One revoked for
// another name is kept.
func TestRevokedHostKeys(t *testing.T) {
	t.Parallel()

	const count = 16

	var (
		text [count]string
		wire [count][]byte
	)

	for i := range count {
		text[i], wire[i] = hostKey(t)
	}

	certified, certificate := hostCertificate(t)

	storeDir, _ := seed(t, "bot")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	lines := []string{
		"@revoked * " + text[0],
		"everywhere.example " + text[0],
		"two.example " + text[1],
		"two.example " + text[2],
		"@revoked two.example " + text[1],
		"kept.example " + text[3],
		"@revoked elsewhere.example,other?.example,kept,kept.example.more,?kept.example " + text[3],
		"spared.example " + text[4],
		"wild.example " + text[4],
		"@revoked *.example,!spared.example " + text[4],
		"hashed.example " + text[5],
		"@revoked " + knownhosts.HashHostname("hashed.example") + " " + text[5],
		"[ported.example]:2222 " + text[6],
		"@revoked [ported.example]:2222 " + text[6],
		"[elsewhere.example]:2222 " + text[7],
		"@revoked elsewhere.example " + text[7],
		"single1.example " + text[8],
		"single.example " + text[8],
		"@revoked single?.example " + text[8],
		"cased.example " + text[9],
		"@revoked Cased.EXAMPLE " + text[9],
		"tick-tack.example " + text[10],
		"@revoked t*ck.example " + text[10],
		"trail.example " + text[11],
		"@revoked trail.example* " + text[11],
		"bang.example " + text[12],
		"@revoked !bang.example,bang.example " + text[12],
		"Upper.Example " + text[13],
		"@revoked upper.example " + text[13],
		"host.example " + text[14],
		"@revoked host*.example " + text[14],
		"mixed.example " + text[15],
		"@revoked " + knownhosts.HashHostname("mixed.example") + ",x " + text[15],
		"@revoked x," + knownhosts.HashHostname("mixed.example") + " " + text[15],
		"certified.example " + certified,
		"@revoked certified.example " + certificate,
	}

	if err := os.WriteFile(knownHosts, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	allow := func(host string) (int, string, string) {
		return run(
			t,
			"key", "allow", "bot",
			"-store", storeDir, "-user", "git", "-host", host, "-known-hosts", knownHosts,
		)
	}

	// Every key of the host revoked: nothing to allow, and the line that
	// revokes is named.
	for host, by := range map[string]int{
		"everywhere.example":    1,
		"wild.example":          10,
		"hashed.example":        12,
		"ported.example":        14,
		"[ported.example]:2222": 14,
		"single1.example":       19,
		"cased.example":         21,
		"tick-tack.example":     23,
		"trail.example":         25,
		"Upper.Example":         29,
		"host.example":          31,
		"certified.example":     36,
	} {
		code, out, errOut := allow(host)
		if code != 1 || out != "" || !strings.Contains(errOut, "no host keys") ||
			!strings.Contains(errOut, "is revoked by line "+strconv.Itoa(by)) {
			t.Fatalf("allow %s, its key revoked by line %d: exit %d: %s %s", host, by, code, out, errOut)
		}
	}

	// A key revoked for another name, another port, or under a '!', stays;
	// and under a hashed name beside other entries, which ssh takes for
	// no host's.
	for _, host := range []string{
		"kept.example", "spared.example", "elsewhere.example", "single.example", "bang.example", "mixed.example",
	} {
		code, out, errOut := allow(host)
		if code != 0 || !strings.Contains(out, host+" as git (1 host keys)") || errOut != "" {
			t.Fatalf("allow %s, its key revoked for another name: exit %d: %s %s", host, code, out, errOut)
		}
	}

	// One key of two revoked: the other is the destination's, and the one
	// left out is said.
	code, out, errOut := allow("two.example")
	if code != 0 || !strings.Contains(out, "(1 host keys)") ||
		!strings.Contains(errOut, "a key of two.example is left out: line 3 is revoked by line 5") {
		t.Fatalf("allow two.example: exit %d: %s %s", code, out, errOut)
	}

	store, err := keystore.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	record, err := store.Lookup("bot")
	if err != nil {
		t.Fatal(err)
	}

	for _, destination := range record.Policy.Destinations {
		if destination.Host != "two.example" {
			continue
		}

		if len(destination.HostKeys) != 1 || !bytes.Equal(destination.HostKeys[0], wire[2]) {
			t.Fatalf("two.example holds %d keys, or the revoked one", len(destination.HostKeys))
		}

		return
	}

	t.Fatal("no destination two.example")
}
