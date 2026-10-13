package agent_test

import (
	"bytes"
	"testing"

	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The allowed path, end to end, on the hardware: a key made in the
// enclave, stored, served, bound, signed for, and the signature verified
// by x/crypto against the public key the agent listed.
func TestSignEndToEnd(t *testing.T) {
	t.Parallel()

	if !enclave.Available() {
		t.Skip("no Secure Enclave reachable from this process")
	}

	r := start(t)
	h := newHost(t)

	made, err := enclave.Generate(enclave.ClassAfterFirstUnlock)
	if err != nil {
		t.Fatal(err)
	}

	blob, point := made.Blob(), made.Public()
	made.Close()

	public, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	record, _ := botKey(t, "bot", github(h))
	record.PublicKey = public
	record.Fingerprint = protocol.Fingerprint(public)

	if err = r.store.Create(record, blob); err != nil {
		t.Fatal(err)
	}

	client := r.client(t)

	keys, err := client.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), public) {
		t.Fatalf("list: %v %v", keys, err)
	}

	if _, err = client.Extension(protocol.ExtensionSessionBind, h.bind(t, sessionID(), false)); err != nil {
		t.Fatal(err)
	}

	data := userauth(sessionID(), "git", public)

	signature, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err = keys[0].Verify(data, signature); err != nil {
		t.Fatalf("the agent's signature does not verify: %v", err)
	}

	if _, err = client.Sign(keys[0], userauth(sessionID(), "root", public)); err == nil {
		t.Fatal("signed for another user")
	}

	// sshsig, on a fresh, unbound connection.
	fresh := r.client(t)

	sig, err := fresh.Sign(keys[0], sshsig("git"))
	if err != nil {
		t.Fatalf("sshsig: %v", err)
	}

	if err = keys[0].Verify(sshsig("git"), sig); err != nil {
		t.Fatalf("the sshsig signature does not verify: %v", err)
	}

	if _, err = fresh.Sign(keys[0], sshsig("file")); err == nil {
		t.Fatal("signed in another namespace")
	}
}
