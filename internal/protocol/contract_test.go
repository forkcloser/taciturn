// The contract of package protocol, from the sources that define it:
//
//   - RFC 9987 section 3: a message is a uint32 length followed by that many
//     bytes, the first of which is the message number. RFC 4251 section 5:
//     a string is a uint32 length and that many bytes; a boolean is one byte,
//     zero false, anything else true; an mpint is a two's-complement
//     big-endian integer with no unnecessary leading zero bytes, a leading
//     zero where the high bit of a positive value would be set, and the empty
//     string for zero.
//   - RFC 9987 section 4.5: a sign request is the key blob, the data and a
//     uint32 of flags. Section 4.4: an identities answer is a uint32 count,
//     then blob and comment per key. Section 4.7: an extension request is a
//     name and extension-specific bytes; the "query" extension's answer lists
//     the supported names.
//   - OpenSSH PROTOCOL.agent section 1: session-bind@openssh.com carries the
//     host key, the session identifier, the signature and an is_forwarding
//     boolean. OpenSSH ssh-agent.c bounds a session identifier at 128 bytes.
//   - RFC 4252 section 7: the data signed for public-key authentication is
//     the session identifier, the byte SSH_MSG_USERAUTH_REQUEST (50), the user
//     name, the service "ssh-connection", the method "publickey", TRUE, the
//     algorithm name and the public key blob.
//   - OpenSSH PROTOCOL.sshsig: the data signed is the bytes "SSHSIG", the
//     namespace, a reserved empty string, the hash algorithm and the hash.
//   - RFC 5656 section 3.1: an ecdsa-sha2-nistp256 public key is the
//     algorithm name, the identifier "nistp256" and the uncompressed point;
//     section 3.1.2: its signature is the algorithm name and a string holding
//     r and s as mpints.
//
// The package's own rules: every decoder consumes its input exactly, so a
// truncated field, an overlong length or a trailing byte is ErrInvalid; a
// message over MaxMessage bytes or a session identifier over MaxSessionID
// is ErrTooLarge; a transport error is passed through, never reclassified.
// The tests here state the contract's fixed points on hand-built bytes;
// bounded_test.go walks every prefix and every extension of each valid
// encoding; fuzz_test.go runs the decoders past the bound.
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

// fixtures are the valid encodings every test starts from, built by hand
// from the wire definitions, never by the package under test.
func str(b []byte) []byte {
	out := []byte{0, 0, 0, byte(len(b))}

	return append(out, b...)
}

func cat(parts ...[]byte) []byte {
	out := make([]byte, 0)
	for _, p := range parts {
		out = append(out, p...)
	}

	return out
}

var (
	keyBlob  = cat(str([]byte("ecdsa-sha2-nistp256")), str([]byte("nistp256")), str(bytes.Repeat([]byte{4}, 65)))
	sessID   = bytes.Repeat([]byte{0xAB}, 32)
	hostKey  = cat(str([]byte("ssh-ed25519")), str(bytes.Repeat([]byte{1}, 32)))
	hostSig  = cat(str([]byte("ssh-ed25519")), str(bytes.Repeat([]byte{2}, 64)))
	userauth = cat(
		str(sessID),
		[]byte{50},
		str([]byte("git")),
		str([]byte("ssh-connection")),
		str([]byte("publickey")),
		[]byte{1},
		str([]byte("ecdsa-sha2-nistp256")),
		str(keyBlob),
	)
	hostbound = cat(
		str(sessID),
		[]byte{50},
		str([]byte("git")),
		str([]byte("ssh-connection")),
		str([]byte("publickey-hostbound-v00@openssh.com")),
		[]byte{1},
		str([]byte("ecdsa-sha2-nistp256")),
		str(keyBlob),
		str(hostKey),
	)
	sshsig = cat(
		[]byte("SSHSIG"),
		str([]byte("git")),
		str(nil),
		str([]byte("sha512")),
		str(bytes.Repeat([]byte{7}, 64)),
	)
	bindBody = cat(str(hostKey), str(sessID), str(hostSig), []byte{0})
	signReq  = cat(str(keyBlob), str(userauth), []byte{0, 0, 0, 0})
)

func TestReadMessageFramesAndCopies(t *testing.T) {
	t.Parallel()

	wire := []byte{0, 0, 0, 3, 13, 0xAA, 0xBB}

	msg, err := protocol.ReadMessage(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if msg.Type != protocol.TypeSignRequest || !bytes.Equal(msg.Payload, []byte{0xAA, 0xBB}) {
		t.Fatalf("got %v %x", msg.Type, msg.Payload)
	}

	wire[5] = 0 // the message owns its bytes

	if msg.Payload[0] != 0xAA {
		t.Fatal("payload aliases the input")
	}
}

func TestReadMessageBounds(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		wire []byte
		want error
	}{
		"zero length":         {[]byte{0, 0, 0, 0}, protocol.ErrInvalid},
		"over MaxMessage":     {[]byte{0, 1, 0, 1}, protocol.ErrTooLarge},
		"short header":        {[]byte{0, 0}, io.ErrUnexpectedEOF},
		"short body":          {[]byte{0, 0, 0, 2, 11}, io.ErrUnexpectedEOF},
		"empty stream":        {nil, io.EOF},
		"max length accepted": {cat([]byte{0, 1, 0, 0}, make([]byte, protocol.MaxMessage)), nil},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := protocol.ReadMessage(bytes.NewReader(c.wire))
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestWriteToFramesAndRoundTrips(t *testing.T) {
	t.Parallel()

	msg := protocol.Message{Type: protocol.TypeSignResponse, Payload: []byte{1, 2, 3}}

	var buf bytes.Buffer

	n, err := msg.WriteTo(&buf)
	if err != nil || n != 8 {
		t.Fatalf("WriteTo: n=%d err=%v", n, err)
	}

	if !bytes.Equal(buf.Bytes(), []byte{0, 0, 0, 4, 14, 1, 2, 3}) {
		t.Fatalf("frame %x", buf.Bytes())
	}

	back, err := protocol.ReadMessage(&buf)
	if err != nil || back.Type != msg.Type || !bytes.Equal(back.Payload, msg.Payload) {
		t.Fatalf("round trip: %+v %v", back, err)
	}

	oversized := protocol.Message{Type: protocol.TypeIdentitiesAnswer, Payload: make([]byte, protocol.MaxMessage)}
	if _, err := oversized.WriteTo(io.Discard); !errors.Is(err, protocol.ErrTooLarge) {
		t.Fatalf("over-size write: %v", err)
	}
}

func TestParseSignRequest(t *testing.T) {
	t.Parallel()

	req, err := protocol.ParseSignRequest(signReq)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(req.KeyBlob, keyBlob) || !bytes.Equal(req.Data, userauth) || req.Flags != 0 {
		t.Fatalf("%+v", req)
	}
}

func TestParseExtensionTakesTheRest(t *testing.T) {
	t.Parallel()

	ext, err := protocol.ParseExtension(cat(str([]byte(protocol.ExtensionSessionBind)), bindBody))
	if err != nil {
		t.Fatal(err)
	}

	if ext.Name != protocol.ExtensionSessionBind || !bytes.Equal(ext.Contents, bindBody) {
		t.Fatalf("%+v", ext)
	}

	query, err := protocol.ParseExtension(str([]byte(protocol.ExtensionQuery)))
	if err != nil || query.Name != protocol.ExtensionQuery || len(query.Contents) != 0 {
		t.Fatalf("%+v %v", query, err)
	}
}

func TestParseSessionBind(t *testing.T) {
	t.Parallel()

	bind, err := protocol.ParseSessionBind(bindBody)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bind.HostKey, hostKey) || !bytes.Equal(bind.SessionID, sessID) ||
		!bytes.Equal(bind.Signature, hostSig) ||
		bind.Forwarding {
		t.Fatalf("%+v", bind)
	}

	forwarding := cat(str(hostKey), str(sessID), str(hostSig), []byte{1})

	bind, err = protocol.ParseSessionBind(forwarding)
	if err != nil || !bind.Forwarding {
		t.Fatalf("forwarding flag: %+v %v", bind, err)
	}

	long := cat(str(hostKey), str(make([]byte, protocol.MaxSessionID+1)), str(hostSig), []byte{0})
	if _, err := protocol.ParseSessionBind(long); !errors.Is(err, protocol.ErrTooLarge) {
		t.Fatalf("session id over bound: %v", err)
	}

	atBound := cat(str(hostKey), str(make([]byte, protocol.MaxSessionID)), str(hostSig), []byte{0})
	if _, err := protocol.ParseSessionBind(atBound); err != nil {
		t.Fatalf("session id at bound: %v", err)
	}
}

func TestParseUserauthRequest(t *testing.T) {
	t.Parallel()

	req, err := protocol.ParseUserauthRequest(userauth)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(req.SessionID, sessID) || req.User != "git" || req.PublicKeyAlgorithm != "ecdsa-sha2-nistp256" ||
		!bytes.Equal(req.KeyBlob, keyBlob) {
		t.Fatalf("%+v", req)
	}

	wrong := map[string][]byte{
		"empty session id":  userauthWith(nil, 50),
		"message number 51": userauthWith(sessID, 51),
		"service": cat(
			str(sessID),
			[]byte{50},
			str([]byte("git")),
			str([]byte("ssh-userauth")),
			str([]byte("publickey")),
			[]byte{1},
			str([]byte("ecdsa-sha2-nistp256")),
			str(keyBlob),
		),
		"method": cat(
			str(sessID),
			[]byte{50},
			str([]byte("git")),
			str([]byte("ssh-connection")),
			str([]byte("password")),
			[]byte{1},
			str([]byte("ecdsa-sha2-nistp256")),
			str(keyBlob),
		),
		"no signature flag": cat(
			str(sessID),
			[]byte{50},
			str([]byte("git")),
			str([]byte("ssh-connection")),
			str([]byte("publickey")),
			[]byte{0},
			str([]byte("ecdsa-sha2-nistp256")),
			str(keyBlob),
		),
		"host-bound with an empty host key": cat(
			str(sessID),
			[]byte{50},
			str([]byte("git")),
			str([]byte("ssh-connection")),
			str([]byte("publickey-hostbound-v00@openssh.com")),
			[]byte{1},
			str([]byte("ecdsa-sha2-nistp256")),
			str(keyBlob),
			str(nil),
		),
		"host-bound without the host key": cat(
			str(sessID),
			[]byte{50},
			str([]byte("git")),
			str([]byte("ssh-connection")),
			str([]byte("publickey-hostbound-v00@openssh.com")),
			[]byte{1},
			str([]byte("ecdsa-sha2-nistp256")),
			str(keyBlob),
		),
		"plain method with a host key appended": cat(userauth, str(hostKey)),
		"sshsig data":                           sshsig,
	}

	for name, data := range wrong {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := protocol.ParseUserauthRequest(data); !errors.Is(err, protocol.ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestParseSSHSigRequest(t *testing.T) {
	t.Parallel()

	req, err := protocol.ParseSSHSigRequest(sshsig)
	if err != nil {
		t.Fatal(err)
	}

	if req.Namespace != "git" || req.HashAlgorithm != "sha512" || len(req.Hash) != 64 {
		t.Fatalf("%+v", req)
	}

	wrong := map[string][]byte{
		"magic": cat(
			[]byte("SSHSIH"),
			str([]byte("git")),
			str(nil),
			str([]byte("sha512")),
			str(bytes.Repeat([]byte{7}, 64)),
		),
		"reserved set": cat(
			[]byte("SSHSIG"),
			str([]byte("git")),
			str([]byte{1}),
			str([]byte("sha512")),
			str(make([]byte, 64)),
		),
		"userauth data": userauth,
	}

	for name, data := range wrong {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := protocol.ParseSSHSigRequest(data); !errors.Is(err, protocol.ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestResponses(t *testing.T) {
	t.Parallel()

	if f := protocol.Failure(); f.Type != protocol.TypeFailure || len(f.Payload) != 0 {
		t.Fatalf("failure %+v", f)
	}

	if s := protocol.Success(); s.Type != protocol.TypeSuccess || len(s.Payload) != 0 {
		t.Fatalf("success %+v", s)
	}

	ids := protocol.IdentitiesAnswer([]protocol.Identity{{Blob: keyBlob, Comment: "bot"}})
	if ids.Type != protocol.TypeIdentitiesAnswer ||
		!bytes.Equal(ids.Payload, cat([]byte{0, 0, 0, 1}, str(keyBlob), str([]byte("bot")))) {
		t.Fatalf("identities %x", ids.Payload)
	}

	none := protocol.IdentitiesAnswer(nil)
	if !bytes.Equal(none.Payload, []byte{0, 0, 0, 0}) {
		t.Fatalf("empty identities %x", none.Payload)
	}

	sig := protocol.SignResponse([]byte{9, 9})
	if sig.Type != protocol.TypeSignResponse || !bytes.Equal(sig.Payload, str([]byte{9, 9})) {
		t.Fatalf("sign response %x", sig.Payload)
	}

	q := protocol.QueryResponse([]string{protocol.ExtensionSessionBind})
	if q.Type != protocol.TypeExtensionResponse ||
		!bytes.Equal(q.Payload, cat(str([]byte("query")), str([]byte(protocol.ExtensionSessionBind)))) {
		t.Fatalf("query response %x", q.Payload)
	}
}

// The key and signature encodings are checked against x/crypto/ssh, the
// implementation every consumer of ours runs: what we emit must parse there
// and come back equal.
func TestECDSAP256EncodingsAgreeWithXCrypto(t *testing.T) {
	t.Parallel()

	point := append([]byte{4}, bytes.Repeat([]byte{0x5A}, 64)...)

	blob, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	want := ssh.Marshal(struct {
		Name, Curve string
		Point       []byte
	}{protocol.AlgorithmECDSAP256, "nistp256", point})
	if !bytes.Equal(blob, want) {
		t.Fatalf("public key blob differs from x/crypto's:\n%x\n%x", blob, want)
	}

	for _, bad := range [][]byte{nil, point[:64], append([]byte{2}, point[1:]...), append(point, 0)} {
		if _, err = protocol.ECDSAP256PublicKey(bad); !errors.Is(err, protocol.ErrInvalid) {
			t.Fatalf("point %x: %v", bad, err)
		}
	}

	r := new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 32)) // high bit set: a leading zero is due
	s := big.NewInt(1)

	sigBlob, err := protocol.ECDSAP256Signature(r, s)
	if err != nil {
		t.Fatal(err)
	}

	wantSig := ssh.Marshal(ssh.Signature{
		Format: protocol.AlgorithmECDSAP256,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{r, s}),
	})
	if !bytes.Equal(sigBlob, wantSig) {
		t.Fatalf("signature blob differs from x/crypto's:\n%x\n%x", sigBlob, wantSig)
	}

	zero, err := protocol.ECDSAP256Signature(big.NewInt(0), big.NewInt(0))
	if err != nil || !bytes.Equal(zero, cat(str([]byte(protocol.AlgorithmECDSAP256)), str(cat(str(nil), str(nil))))) {
		t.Fatalf("zero mpints: %x %v", zero, err)
	}

	if _, err = protocol.ECDSAP256Signature(big.NewInt(-1), s); !errors.Is(err, protocol.ErrInvalid) {
		t.Fatalf("negative r: %v", err)
	}
}

func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	t.Parallel()

	// ssh-keygen -lf on this key prints the fingerprint below.
	pub, _, _, _, err := ssh.ParseAuthorizedKey(
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := protocol.Fingerprint(pub.Marshal()), ssh.FingerprintSHA256(pub); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestTypeString(t *testing.T) {
	t.Parallel()

	if protocol.TypeSignRequest.String() != "sign-request" || protocol.Type(99).String() != "type-99" {
		t.Fatal(protocol.TypeSignRequest.String(), protocol.Type(99).String())
	}
}

// userauthWith is the userauth fixture with its session identifier and
// message number chosen, the rest as the fixture has them.
func userauthWith(sid []byte, msg byte) []byte {
	return cat(
		str(sid),
		[]byte{msg},
		str([]byte("git")),
		str([]byte("ssh-connection")),
		str([]byte("publickey")),
		[]byte{1},
		str([]byte("ecdsa-sha2-nistp256")),
		str(keyBlob),
	)
}

// The host-bound method carries the server's host key after the public
// key and nothing else differs; the plain method carries no host key.
func TestParseUserauthRequestHostbound(t *testing.T) {
	t.Parallel()

	req, err := protocol.ParseUserauthRequest(hostbound)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(req.SessionID, sessID) || req.User != "git" || req.PublicKeyAlgorithm != "ecdsa-sha2-nistp256" ||
		!bytes.Equal(req.KeyBlob, keyBlob) || !bytes.Equal(req.HostKey, hostKey) {
		t.Fatalf("%+v", req)
	}

	plain, err := protocol.ParseUserauthRequest(userauth)
	if err != nil {
		t.Fatal(err)
	}

	if plain.HostKey != nil {
		t.Fatalf("plain request carries a host key: %x", plain.HostKey)
	}
}
