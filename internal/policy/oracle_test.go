package policy_test

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The decision as docs/design.md states it ("Policy, and the decision the
// agent makes", rules 2 to 5), written over the decoded request rather
// than over the table's dimensions, and fed generated inputs: several
// destinations with several host keys each, users and namespaces that
// collide or are empty, and peer lists with every entry shape, the glob
// patterns filepath.Match takes and the one it refuses. The two readings of
// the design, the table's and this one, must agree with the package on
// every input.

// The generated world: three host keys, three users, three namespaces, and
// the peers a policy may name.
var (
	hosts = [][]byte{
		ssh.Marshal(struct{ Name, Key string }{"ssh-ed25519", "host zero"}),
		ssh.Marshal(struct{ Name, Key string }{"ssh-ed25519", "host one"}),
		ssh.Marshal(struct{ Name, Key string }{"ssh-rsa", "host two"}),
	}
	users       = []string{"git", "", "root"}
	namespaces  = []string{"git", "", "file"}
	peerPath    = "/opt/openssh/1.0/bin/ssh"
	peerEntries = []string{
		policy.PeerAny,
		policy.PeerPathPrefix + peerPath,
		policy.PeerPathPrefix + "/opt/openssh/*/bin/ssh",
		policy.PeerPathPrefix + "/opt/openssh/*/bin/ssh-keygen",
		policy.PeerPathPrefix + "[",
		`anchor apple and identifier "com.apple.ssh"`,
		`identifier "nobody"`,
	}
	satisfied = []string{`anchor apple and identifier "com.apple.ssh"`}
	keyBlobs  = [][]byte{
		ssh.Marshal(struct{ Name, Curve, Point string }{protocol.AlgorithmECDSAP256, "nistp256", "key zero"}),
		ssh.Marshal(struct{ Name, Curve, Point string }{protocol.AlgorithmECDSAP256, "nistp256", "key one"}),
	}
	sessions = [][]byte{[]byte("session zero"), []byte("session one")}
)

// world is one generated input, decoded from the fuzz arguments.
type world struct {
	conn policy.Connection
	pol  policy.Policy
	key  []byte
	data []byte
	// What the data is, as the generator built it; the model judges from
	// this, never from the bytes.
	kind      uint8 // 0 userauth, 1 hostbound, 2 sshsig, 3 garbage
	sid       []byte
	reqHost   []byte
	reqKey    []byte
	reqUser   string
	reqAlg    string
	namespace string
}

func pick[T any](from []T, sel uint8) T { return from[int(sel)%len(from)] }

// selectors is one generated world's choice of everything, as the fuzz
// arguments carry it: three flags in one byte, two words of four
// selectors each, and two masks.
type selectors struct {
	bound, forwarding, refused bool
	kind                       uint8
	hostSel, sidSel, keySel    uint8
	userSel, reqHostSel        uint8
	reqKeySel, algSel, nsSel   uint8
	destMask, peerMask         uint8
}

func decode(flags, kind uint8, selA, selB uint32, destMask, peerMask uint8) selectors {
	return selectors{
		bound: flags&1 != 0, forwarding: flags&2 != 0, refused: flags&4 != 0,
		kind:    kind,
		hostSel: uint8(selA), sidSel: uint8(selA >> 8), keySel: uint8(selA >> 16), userSel: uint8(selA >> 24),
		reqHostSel: uint8(selB), reqKeySel: uint8(selB >> 8), algSel: uint8(selB >> 16), nsSel: uint8(selB >> 24),
		destMask: destMask, peerMask: peerMask,
	}
}

func build(sel selectors) world {
	bound, forwarding, refused := sel.bound, sel.forwarding, sel.refused
	kind, hostSel, sidSel, keySel := sel.kind, sel.hostSel, sel.sidSel, sel.keySel
	userSel, reqHostSel, reqKeySel, algSel, nsSel := sel.userSel, sel.reqHostSel, sel.reqKeySel, sel.algSel, sel.nsSel
	destMask, peerMask := sel.destMask, sel.peerMask

	w := world{kind: kind % 4}
	w.conn = policy.Connection{Peer: policy.Peer{Path: peerPath, Satisfied: satisfied}, BindRefused: refused}

	if bound {
		w.conn.Bound = true
		w.conn.Forwarding = forwarding
		w.conn.HostKey = pick(hosts, hostSel)
		w.conn.SessionID = pick(sessions, sidSel)
	}

	w.key = pick(keyBlobs, keySel)

	// Destinations: bit i of destMask names destination i, user i % 3,
	// with the host keys whose bit is set in the high bits.
	for i := range uint8(4) {
		if destMask&(1<<i) == 0 {
			continue
		}

		dest := policy.Destination{User: pick(users, i), Host: "label"}

		for j := range uint8(3) {
			if (destMask>>4)&(1<<j) != 0 || i == j {
				dest.HostKeys = append(dest.HostKeys, hosts[j])
			}
		}

		w.pol.Destinations = append(w.pol.Destinations, dest)
	}

	for i := range uint8(3) {
		if (nsSel>>4)&(1<<i) != 0 {
			w.pol.Namespaces = append(w.pol.Namespaces, namespaces[i])
		}
	}

	for i := range uint8(7) {
		if peerMask&(1<<i) != 0 {
			w.pol.Peers = append(w.pol.Peers, peerEntries[i])
		}
	}

	w.sid = pick(sessions, sidSel>>4)
	w.reqHost = pick(hosts, reqHostSel)
	w.reqKey = pick(keyBlobs, reqKeySel)
	w.reqUser = pick(users, userSel)
	w.reqAlg = pick([]string{protocol.AlgorithmECDSAP256, "ssh-ed25519"}, algSel)
	w.namespace = pick(namespaces, nsSel)

	switch w.kind {
	case 0:
		w.data = ssh.Marshal(struct {
			SID       []byte
			Msg       byte
			User      string
			Service   string
			Method    string
			Signed    bool
			Algorithm string
			Key       []byte
		}{w.sid, 50, w.reqUser, "ssh-connection", "publickey", true, w.reqAlg, w.reqKey})
	case 1:
		w.data = ssh.Marshal(struct {
			SID       []byte
			Msg       byte
			User      string
			Service   string
			Method    string
			Signed    bool
			Algorithm string
			Key       []byte
			Host      []byte
		}{w.sid, 50, w.reqUser, "ssh-connection", "publickey-hostbound-v00@openssh.com", true, w.reqAlg, w.reqKey, w.reqHost})
	case 2:
		w.data = append([]byte("SSHSIG"), ssh.Marshal(struct {
			Namespace, Reserved, Hash string
			Digest                    []byte
		}{w.namespace, "", "sha512", []byte("digest")})...)
	default:
		w.data = []byte("not a request at all")
	}

	return w
}

// The design's rules.

func (w world) destinationsForBoundHost() []policy.Destination {
	var out []policy.Destination

	for _, d := range w.pol.Destinations {
		if slices.ContainsFunc(d.HostKeys, func(k []byte) bool { return bytes.Equal(k, w.conn.HostKey) }) {
			out = append(out, d)
		}
	}

	return out
}

func (w world) peerAllowed() bool {
	for _, entry := range w.pol.Peers {
		switch {
		case entry == policy.PeerAny:
			return true
		case len(entry) > len(policy.PeerPathPrefix) && entry[:len(policy.PeerPathPrefix)] == policy.PeerPathPrefix:
			// A pattern the matcher refuses admits nobody.
			if ok, err := filepath.Match(entry[len(policy.PeerPathPrefix):], w.conn.Peer.Path); err == nil && ok {
				return true
			}
		case slices.Contains(w.conn.Peer.Satisfied, entry):
			return true
		}
	}

	return false
}

func (w world) modelSign() policy.Decision {
	switch {
	case w.conn.Bound && w.conn.Forwarding:
		return policy.Decision{Rule: policy.RuleForwarding}
	case w.conn.BindRefused:
		return policy.Decision{Rule: policy.RuleBindRefused}
	case w.conn.Bound:
		// Rule 4: a userauth request, plain or host-bound, agreeing with
		// the binding on every field, for a user a destination allows.
		if w.kind > 1 {
			return policy.Decision{Rule: policy.RuleNotUserauth}
		}

		if !bytes.Equal(w.sid, w.conn.SessionID) {
			return policy.Decision{Rule: policy.RuleSessionID}
		}

		if w.kind == 1 && !bytes.Equal(w.reqHost, w.conn.HostKey) {
			return policy.Decision{Rule: policy.RuleHostKey}
		}

		if !bytes.Equal(w.reqKey, w.key) {
			return policy.Decision{Rule: policy.RuleKeyMismatch}
		}

		if w.reqAlg != protocol.AlgorithmECDSAP256 {
			return policy.Decision{Rule: policy.RuleAlgorithm}
		}

		if !slices.ContainsFunc(
			w.destinationsForBoundHost(),
			func(d policy.Destination) bool { return d.User == w.reqUser },
		) {
			return policy.Decision{Rule: policy.RuleUser}
		}

		if !w.peerAllowed() {
			return policy.Decision{Rule: policy.RulePeer}
		}

		return policy.Decision{Allowed: true, Rule: policy.RuleAllowedAuth}
	default:
		// Rule 5: an SSHSIG request in an allowed namespace.
		if w.kind != 2 {
			return policy.Decision{Rule: policy.RuleNotSSHSig}
		}

		if !slices.Contains(w.pol.Namespaces, w.namespace) {
			return policy.Decision{Rule: policy.RuleNamespace}
		}

		if !w.peerAllowed() {
			return policy.Decision{Rule: policy.RulePeer}
		}

		return policy.Decision{Allowed: true, Rule: policy.RuleAllowedSSHSig}
	}
}

func (w world) modelVisible() policy.Decision {
	switch {
	case w.conn.Bound && w.conn.Forwarding:
		return policy.Decision{Rule: policy.RuleForwarding}
	case w.conn.BindRefused:
		return policy.Decision{Rule: policy.RuleBindRefused}
	case !w.conn.Bound:
		// Rule 3: unbound, every key with a non-empty policy.
		if len(w.pol.Destinations) == 0 && len(w.pol.Namespaces) == 0 {
			return policy.Decision{Rule: policy.RuleNothing}
		}

		return policy.Decision{Allowed: true, Rule: policy.RuleVisible}
	case len(w.destinationsForBoundHost()) == 0:
		return policy.Decision{Rule: policy.RuleNoDestination}
	default:
		return policy.Decision{Allowed: true, Rule: policy.RuleVisibleBound}
	}
}

// word packs four selectors into one fuzz argument.
func word(a, b, c, d uint8) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

func FuzzDecisionAgainstTheDesign(f *testing.F) {
	// Bound, a plain userauth request agreeing with everything.
	f.Add(uint8(1), uint8(0), word(0, 0, 0, 0), word(0, 0, 0, 0x10), uint8(0x11), uint8(1))
	// Unbound, an SSHSIG request in the git namespace.
	f.Add(uint8(0), uint8(2), word(0, 0, 0, 0), word(0, 0, 0, 0x10), uint8(0x01), uint8(4))
	// Bound for forwarding, a host-bound request.
	f.Add(uint8(3), uint8(1), word(2, 0x10, 1, 2), word(2, 1, 1, 0x70), uint8(0x7F), uint8(0x7F))
	// Bound after a refused binding, garbage.
	f.Add(uint8(5), uint8(3), word(1, 0x01, 0, 1), word(0, 0, 0, 0), uint8(0x00), uint8(0x10))
	// Unbound, a policy with namespaces and no destinations, and the
	// reverse: each is a non-empty policy, so the key is listed.
	f.Add(uint8(0), uint8(2), word(0, 0, 0, 0), word(0, 0, 0, 0x10), uint8(0x00), uint8(1))
	f.Add(uint8(0), uint8(2), word(0, 0, 0, 0), word(0, 0, 0, 0x00), uint8(0x01), uint8(1))

	f.Fuzz(func(t *testing.T, flags, kind uint8, selA, selB uint32, destMask, peerMask uint8) {
		w := build(decode(flags, kind, selA, selB, destMask, peerMask))

		if got, want := policy.Sign(w.conn, w.pol, w.key, w.data), w.modelSign(); got != want {
			t.Fatalf("Sign: got %+v, the design says %+v\n%+v", got, want, w)
		}

		if got, want := policy.Visible(w.conn, w.pol), w.modelVisible(); got != want {
			t.Fatalf("Visible: got %+v, the design says %+v\n%+v", got, want, w)
		}
	})
}
