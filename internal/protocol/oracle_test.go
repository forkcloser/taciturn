package protocol_test

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// x/crypto/ssh's Marshal and Unmarshal are an encoder and a decoder of the
// RFC 4251 wire types written by other hands: what they produce from a
// struct is what each decoder here must read back field for field, and
// what each encoder here produces is what they must read back. The hand
// fixtures of contract_test.go encode every length in one byte; the values
// here are generated, so lengths of two, three and four bytes, empty
// strings and strings at a message's bound are reached too.

// The wire shapes, as x/crypto marshals them (field order is the encoding).
type (
	wireUserauth struct {
		SessionID []byte
		Msg       byte
		User      string
		Service   string
		Method    string
		Signed    bool
		Algorithm string
		KeyBlob   []byte
	}
	wireHostbound struct {
		SessionID []byte
		Msg       byte
		User      string
		Service   string
		Method    string
		Signed    bool
		Algorithm string
		KeyBlob   []byte
		HostKey   []byte
	}
	wireSSHSig struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    []byte
	}
	wireSignRequest struct {
		KeyBlob []byte
		Data    []byte
		Flags   uint32
	}
	wireSessionBind struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	wireExtension struct {
		Name string
		Rest []byte `ssh:"rest"`
	}
	wireIdentity struct {
		Blob    []byte
		Comment string
	}
	wireIdentities struct {
		Count uint32
		Rest  []byte `ssh:"rest"`
	}
	wireSignature struct {
		Blob []byte
	}
	wirePublicKey struct {
		Algorithm string
		Curve     string
		Point     []byte
	}
)

// fill is a deterministic byte string of the length asked, never all one
// value, so a decoder that mixes two fields of the same length is caught.
func fill(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i*7)
	}

	return out
}

func FuzzParseUserauthRequestAgainstXCrypto(f *testing.F) {
	f.Add("git", uint8(32), uint16(104), false, uint16(0))
	f.Add("", uint8(1), uint16(300), true, uint16(300))
	f.Add("a user with spaces and ünïcode", uint8(255), uint16(65535), true, uint16(1))

	f.Fuzz(func(t *testing.T, user string, sidLen uint8, keyLen uint16, hostbound bool, hostLen uint16) {
		sid := fill(int(sidLen), 1)
		key := fill(int(keyLen), 2)
		host := fill(int(hostLen), 3)

		var data []byte

		method := "publickey"
		if hostbound {
			method = "publickey-hostbound-v00@openssh.com"
			data = ssh.Marshal(
				wireHostbound{sid, 50, user, "ssh-connection", method, true, "ecdsa-sha2-nistp256", key, host},
			)
		} else {
			data = ssh.Marshal(wireUserauth{sid, 50, user, "ssh-connection", method, true, "ecdsa-sha2-nistp256", key})
		}

		got, err := protocol.ParseUserauthRequest(data)

		switch {
		case sidLen == 0 || (hostbound && hostLen == 0):
			// The package's own two refusals past the wire shape.
			if !errors.Is(err, protocol.ErrInvalid) {
				t.Fatalf("empty session id or host key: %v", err)
			}

			return
		case err != nil:
			t.Fatalf("x/crypto's encoding refused: %v", err)
		}

		if !bytes.Equal(got.SessionID, sid) || got.User != user || got.PublicKeyAlgorithm != "ecdsa-sha2-nistp256" ||
			!bytes.Equal(got.KeyBlob, key) {
			t.Fatalf("fields differ: %+v", got)
		}

		if hostbound && !bytes.Equal(got.HostKey, host) {
			t.Fatalf("host key differs: %x", got.HostKey)
		}

		if !hostbound && got.HostKey != nil {
			t.Fatalf("a plain request carries a host key: %x", got.HostKey)
		}
	})
}

func FuzzParseSSHSigRequestAgainstXCrypto(f *testing.F) {
	f.Add("git", "sha512", uint8(64))
	f.Add("", "", uint8(0))
	f.Add("file", "sha256", uint8(255))

	f.Fuzz(func(t *testing.T, namespace, hash string, digestLen uint8) {
		digest := fill(int(digestLen), 5)
		data := append([]byte("SSHSIG"), ssh.Marshal(wireSSHSig{namespace, "", hash, digest})...)

		got, err := protocol.ParseSSHSigRequest(data)
		if err != nil {
			t.Fatalf("x/crypto's encoding refused: %v", err)
		}

		if got.Namespace != namespace || got.HashAlgorithm != hash || !bytes.Equal(got.Hash, digest) {
			t.Fatalf("fields differ: %+v", got)
		}
	})
}

func FuzzParseSignRequestAgainstXCrypto(f *testing.F) {
	f.Add(uint16(104), uint16(200), uint32(0))
	f.Add(uint16(0), uint16(0), uint32(0xFFFFFFFF))
	f.Add(uint16(65535), uint16(1), uint32(2))

	f.Fuzz(func(t *testing.T, keyLen, dataLen uint16, flags uint32) {
		key, data := fill(int(keyLen), 7), fill(int(dataLen), 11)

		got, err := protocol.ParseSignRequest(ssh.Marshal(wireSignRequest{key, data, flags}))
		if err != nil {
			t.Fatalf("x/crypto's encoding refused: %v", err)
		}

		if !bytes.Equal(got.KeyBlob, key) || !bytes.Equal(got.Data, data) || got.Flags != flags {
			t.Fatalf("fields differ: %+v", got)
		}
	})
}

func FuzzParseSessionBindAgainstXCrypto(f *testing.F) {
	f.Add(uint16(51), uint8(32), uint16(83), false)
	f.Add(uint16(0), uint8(128), uint16(0), true)
	f.Add(uint16(300), uint8(129), uint16(300), true)

	f.Fuzz(func(t *testing.T, hostLen uint16, sidLen uint8, sigLen uint16, forwarding bool) {
		host, sid, sig := fill(int(hostLen), 13), fill(int(sidLen), 17), fill(int(sigLen), 19)

		got, err := protocol.ParseSessionBind(ssh.Marshal(wireSessionBind{host, sid, sig, forwarding}))
		if int(sidLen) > agentMaxSIDLen {
			if !errors.Is(err, protocol.ErrTooLarge) {
				t.Fatalf("session id of %d bytes: %v", sidLen, err)
			}

			return
		}

		if err != nil {
			t.Fatalf("x/crypto's encoding refused: %v", err)
		}

		if !bytes.Equal(got.HostKey, host) || !bytes.Equal(got.SessionID, sid) || !bytes.Equal(got.Signature, sig) ||
			got.Forwarding != forwarding {
			t.Fatalf("fields differ: %+v", got)
		}
	})
}

func FuzzParseExtensionAgainstXCrypto(f *testing.F) {
	f.Add("session-bind@openssh.com", uint16(0))
	f.Add("", uint16(300))
	f.Add("query", uint16(65535))

	f.Fuzz(func(t *testing.T, name string, restLen uint16) {
		rest := fill(int(restLen), 23)

		got, err := protocol.ParseExtension(ssh.Marshal(wireExtension{name, rest}))
		if err != nil {
			t.Fatalf("x/crypto's encoding refused: %v", err)
		}

		if got.Name != name || !bytes.Equal(got.Contents, rest) {
			t.Fatalf("fields differ: %+v", got)
		}
	})
}

// The encoders, read back by x/crypto: an identities answer with comments
// and blobs of every length, a sign response, a query answer, and the
// framing of a message of every size up to the bound.
func FuzzEncodersAgainstXCrypto(f *testing.F) {
	f.Add(uint8(1), uint16(104), "bot", uint16(100))
	f.Add(uint8(0), uint16(0), "", uint16(0))
	f.Add(uint8(7), uint16(300), "a comment of some length, with ünïcode", uint16(65535))

	f.Fuzz(func(t *testing.T, count uint8, blobLen uint16, comment string, sigLen uint16) {
		identities := make([]protocol.Identity, int(count))
		for i := range identities {
			identities[i] = protocol.Identity{Blob: fill(int(blobLen), byte(i)), Comment: comment}
		}

		answer := protocol.IdentitiesAnswer(identities)
		if answer.Type != protocol.TypeIdentitiesAnswer {
			t.Fatalf("type %v", answer.Type)
		}

		var head wireIdentities
		if err := ssh.Unmarshal(answer.Payload, &head); err != nil {
			t.Fatalf("x/crypto cannot read the answer: %v", err)
		}

		if head.Count != uint32(count) {
			t.Fatalf("count %d, want %d", head.Count, count)
		}

		rest := head.Rest

		for i := range identities {
			var id wireIdentity

			var tail struct {
				Rest []byte `ssh:"rest"`
			}

			combined := struct {
				Blob    []byte
				Comment string
				Rest    []byte `ssh:"rest"`
			}{}
			if err := ssh.Unmarshal(rest, &combined); err != nil {
				t.Fatalf("identity %d: %v", i, err)
			}

			id.Blob, id.Comment, tail.Rest = combined.Blob, combined.Comment, combined.Rest
			if !bytes.Equal(id.Blob, identities[i].Blob) || id.Comment != comment {
				t.Fatalf("identity %d differs: %+v", i, id)
			}

			rest = tail.Rest
		}

		if len(rest) != 0 {
			t.Fatalf("%d bytes after the last identity", len(rest))
		}

		sig := fill(int(sigLen), 29)
		response := protocol.SignResponse(sig)

		var readSig wireSignature
		if err := ssh.Unmarshal(response.Payload, &readSig); err != nil || !bytes.Equal(readSig.Blob, sig) {
			t.Fatalf("sign response: %v %x", err, readSig.Blob)
		}

		// Framing: what WriteTo wrote, ReadMessage reads, up to the bound;
		// one over is refused on the way out and on the way in.
		if len(answer.Payload)+1 <= protocol.MaxMessage {
			var framed bytes.Buffer

			n, err := answer.WriteTo(&framed)
			if err != nil || n != int64(framed.Len()) || framed.Len() != 4+1+len(answer.Payload) {
				t.Fatalf("WriteTo: %d %v (%d bytes)", n, err, framed.Len())
			}

			back, err := protocol.ReadMessage(&framed)
			if err != nil || back.Type != answer.Type || !bytes.Equal(back.Payload, answer.Payload) {
				t.Fatalf("ReadMessage: %v %+v", err, back)
			}

			if framed.Len() != 0 {
				t.Fatalf("%d bytes left after the frame", framed.Len())
			}
		} else if n, err := answer.WriteTo(io.Discard); !errors.Is(err, protocol.ErrTooLarge) || n != 0 {
			t.Fatalf("a message over the bound was written: %d %v", n, err)
		}
	})
}

// The numbers and bounds the sources fix, as literals: RFC 9987 section
// 5.1 and OpenSSH's authfd.h for the message numbers, ssh-agent.c's
// AGENT_MAX_SID_LEN for the session identifier.
const agentMaxSIDLen = 128

func TestNumbersAndBoundsAreTheSources(t *testing.T) {
	t.Parallel()

	numbers := map[protocol.Type]byte{
		protocol.TypeFailure: 5, protocol.TypeSuccess: 6, protocol.TypeRequestIdentities: 11,
		protocol.TypeIdentitiesAnswer: 12, protocol.TypeSignRequest: 13, protocol.TypeSignResponse: 14,
		protocol.TypeAddIdentity: 17, protocol.TypeRemoveIdentity: 18, protocol.TypeRemoveAllIdentities: 19,
		protocol.TypeAddSmartcardKey: 20, protocol.TypeRemoveSmartcardKey: 21, protocol.TypeLock: 22,
		protocol.TypeUnlock: 23, protocol.TypeAddIDConstrained: 25, protocol.TypeAddSmartcardConstrained: 26,
		protocol.TypeExtension: 27, protocol.TypeExtensionFailure: 28, protocol.TypeExtensionResponse: 29,
	}
	for typ, want := range numbers {
		if byte(typ) != want {
			t.Errorf("%s is %d, the RFC says %d", typ, byte(typ), want)
		}
	}

	if protocol.MaxSessionID != agentMaxSIDLen {
		t.Errorf("MaxSessionID = %d, OpenSSH's is %d", protocol.MaxSessionID, agentMaxSIDLen)
	}

	if protocol.MaxMessage != 64*1024 {
		t.Errorf("MaxMessage = %d, the package says 64 KiB", protocol.MaxMessage)
	}
}

// The query answer is one extension response x/crypto's client reads as
// a list of names; and the ECDSA key and signature blobs, read back by
// x/crypto's parsers rather than compared to its marshalling.
func TestQueryAndKeyBlobsReadBackByXCrypto(t *testing.T) {
	t.Parallel()

	names := []string{
		"session-bind@openssh.com",
		"query",
		"",
		"a name of more than two hundred and fifty-five characters " + string(fill(300, 'a')),
	}

	var ext wireExtension
	if err := ssh.Unmarshal(protocol.QueryResponse(names).Payload, &ext); err != nil || ext.Name != "query" {
		t.Fatalf("query response: %v %+v", err, ext)
	}

	rest := ext.Rest
	for i, want := range names {
		var next struct {
			Name string
			Rest []byte `ssh:"rest"`
		}

		if err := ssh.Unmarshal(rest, &next); err != nil || next.Name != want {
			t.Fatalf("name %d: %v %q, want %q", i, err, next.Name, want)
		}

		rest = next.Rest
	}

	if len(rest) != 0 {
		t.Fatalf("%d bytes after the last name", len(rest))
	}

	point := append([]byte{4}, fill(64, 31)...)

	blob, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	var key wirePublicKey
	if keyErr := ssh.Unmarshal(
		blob,
		&key,
	); keyErr != nil || key.Algorithm != "ecdsa-sha2-nistp256" ||
		key.Curve != "nistp256" ||
		!bytes.Equal(key.Point, point) {
		t.Fatalf("public key blob: %v %+v", keyErr, key)
	}

	back, err := protocol.ECDSAP256PublicKeyPoint(ssh.Marshal(key))
	if err != nil || !bytes.Equal(back, point) {
		t.Fatalf("point from x/crypto's encoding: %v %x", err, back)
	}

	// Every mpint shape: zero, a high bit set (a leading zero is due), a
	// value under 256 and one of full width, read back by x/crypto's
	// *big.Int unmarshalling, which refuses an unnecessary leading zero.
	for _, pair := range [][2]*big.Int{
		{big.NewInt(0), big.NewInt(0)},
		{big.NewInt(1), big.NewInt(255)},
		{new(big.Int).SetBytes(fill(32, 0x80)), new(big.Int).SetBytes(fill(32, 0x01))},
		{new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 32)), new(big.Int).SetBytes(bytes.Repeat([]byte{0x7F}, 32))},
	} {
		sigBlob, sigErr := protocol.ECDSAP256Signature(pair[0], pair[1])
		if sigErr != nil {
			t.Fatal(sigErr)
		}

		var sig ssh.Signature
		if err := ssh.Unmarshal(sigBlob, &sig); err != nil || sig.Format != "ecdsa-sha2-nistp256" {
			t.Fatalf("signature blob: %v %+v", err, sig)
		}

		var rs struct{ R, S *big.Int }
		if err := ssh.Unmarshal(sig.Blob, &rs); err != nil || rs.R.Cmp(pair[0]) != 0 || rs.S.Cmp(pair[1]) != 0 {
			t.Fatalf("r, s from %v: %v %v %v", pair, err, rs.R, rs.S)
		}
	}
}
