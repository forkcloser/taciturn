package policy_test

import (
	"bytes"
	"testing"

	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// The decision table has a handful of independent dimensions. The walk
// enumerates every combination of them, builds the inputs that realise it,
// and holds the package to the expected outcome stated below as the rule
// order of the package comment, written over the dimensions rather than
// over bytes, so the two cannot be wrong the same way.
type dims struct {
	bound, forwarding, bindRefused bool
	// dataKind: the shape of the data the client asks to have signed.
	dataKind string
	// For a userauth request: do its fields agree with the binding and the
	// policy? For an sshsig request: is its namespace allowed?
	sessionMatch, keyMatch, algorithmMatch, userMatch, namespaceMatch bool
	// For a userauth request: is it host-bound, and does the host key it
	// names agree with the binding?
	hostbound, hostKeyMatch bool
	// Does a destination of the policy carry the bound host key? Does the
	// policy allow anything? Is the peer named?
	hostKnown, policyEmpty, peerAllowed bool
}

const (
	kindUserauth = "userauth"
	kindSSHSig   = "sshsig"
	kindGarbage  = "garbage"
)

func (d dims) expectedSign() policy.Decision {
	switch {
	case d.bound && d.forwarding:
		return policy.Decision{Rule: policy.RuleForwarding}
	case d.bindRefused:
		return policy.Decision{Rule: policy.RuleBindRefused}
	case d.bound:
		switch {
		case d.dataKind != kindUserauth:
			return policy.Decision{Rule: policy.RuleNotUserauth}
		case !d.sessionMatch:
			return policy.Decision{Rule: policy.RuleSessionID}
		case d.hostbound && !d.hostKeyMatch:
			return policy.Decision{Rule: policy.RuleHostKey}
		case !d.keyMatch:
			return policy.Decision{Rule: policy.RuleKeyMismatch}
		case !d.algorithmMatch:
			return policy.Decision{Rule: policy.RuleAlgorithm}
		case d.policyEmpty || !d.hostKnown || !d.userMatch:
			return policy.Decision{Rule: policy.RuleUser}
		case !d.peerAllowed:
			return policy.Decision{Rule: policy.RulePeer}
		default:
			return policy.Decision{Allowed: true, Rule: policy.RuleAllowedAuth}
		}
	default:
		switch {
		case d.dataKind != kindSSHSig:
			return policy.Decision{Rule: policy.RuleNotSSHSig}
		case d.policyEmpty || !d.namespaceMatch:
			return policy.Decision{Rule: policy.RuleNamespace}
		case !d.peerAllowed:
			return policy.Decision{Rule: policy.RulePeer}
		default:
			return policy.Decision{Allowed: true, Rule: policy.RuleAllowedSSHSig}
		}
	}
}

func (d dims) expectedVisible() policy.Decision {
	switch {
	case d.bound && d.forwarding:
		return policy.Decision{Rule: policy.RuleForwarding}
	case d.bindRefused:
		return policy.Decision{Rule: policy.RuleBindRefused}
	case !d.bound && d.policyEmpty:
		return policy.Decision{Rule: policy.RuleNothing}
	case !d.bound:
		return policy.Decision{Allowed: true, Rule: policy.RuleVisible}
	case !d.policyEmpty && d.hostKnown:
		return policy.Decision{Allowed: true, Rule: policy.RuleVisibleBound}
	default:
		return policy.Decision{Rule: policy.RuleNoDestination}
	}
}

// realise builds the connection, policy and data that have exactly the
// dimensions' properties.
func (d dims) realise() (policy.Connection, policy.Policy, []byte) {
	conn := policy.Connection{Peer: policy.Peer{Path: "/usr/bin/ssh"}, BindRefused: d.bindRefused}
	if d.bound {
		conn.Bound = true
		conn.Forwarding = d.forwarding
		conn.SessionID = sessionID
		conn.HostKey = otherHostKey

		if d.hostKnown {
			conn.HostKey = githubKey
		}
	}

	pol := github()
	if d.policyEmpty {
		pol.Destinations = nil
		pol.Namespaces = nil
	}

	if !d.peerAllowed {
		pol.Peers = nil
	}

	var data []byte

	switch d.dataKind {
	case kindUserauth:
		sid, key, alg, user := sessionID, keyBlob, protocol.AlgorithmECDSAP256, "git"
		if !d.sessionMatch {
			sid = otherSession
		}

		if !d.keyMatch {
			key = otherKeyBlob
		}

		if !d.algorithmMatch {
			alg = "ssh-ed25519"
		}

		if !d.userMatch {
			user = "root"
		}

		data = userauthFor(sid, user, alg, key)

		if d.hostbound {
			host := conn.HostKey
			if !d.hostKeyMatch {
				host = otherHostKey
				if bytes.Equal(conn.HostKey, otherHostKey) {
					host = githubKey
				}
			}

			data = hostboundFor(sid, user, alg, key, host)
		}
	case kindSSHSig:
		ns := "git"
		if !d.namespaceMatch {
			ns = "file"
		}

		data = sshsigFor(ns)
	default:
		data = []byte("not a request")
	}

	return conn, pol, data
}

func TestEveryCombinationOfTheTable(t *testing.T) {
	t.Parallel()

	bools := []bool{false, true}
	kinds := []string{kindUserauth, kindSSHSig, kindGarbage}
	count := 0

	for _, bound := range bools {
		for _, forwarding := range bools {
			for _, refused := range bools {
				for _, kind := range kinds {
					for _, session := range bools {
						for _, key := range bools {
							for _, alg := range bools {
								for _, user := range bools {
									for _, ns := range bools {
										for _, host := range bools {
											for _, empty := range bools {
												for _, peer := range bools {
													for _, hb := range bools {
														for _, hk := range bools {
															d := dims{
																bound,
																forwarding,
																refused,
																kind,
																session,
																key,
																alg,
																user,
																ns,
																hb,
																hk,
																host,
																empty,
																peer,
															}
															conn, pol, data := d.realise()

															if got, want := policy.Sign(
																conn,
																pol,
																keyBlob,
																data,
															), d.expectedSign(); got != want {
																t.Fatalf("%+v: Sign got %+v want %+v", d, got, want)
															}

															if got, want := policy.Visible(
																conn,
																pol,
															), d.expectedVisible(); got != want {
																t.Fatalf("%+v: Visible got %+v want %+v", d, got, want)
															}

															count++
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if count != 2*2*2*3*2*2*2*2*2*2*2*2*2*2 {
		t.Fatalf("walked %d combinations", count)
	}
}
