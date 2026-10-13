// Package policy decides what the agent answers: whether a key is listed to
// a connection and whether a signature request is honoured, from facts the
// agent has already established, never from bytes it has not checked.
//
// The facts are a Connection, which says who connected and what the
// connection is bound to, and a Policy, what the key's owner allowed. The
// decision is a Decision: allowed or refused, with the rule that decided,
// for the audit log. The package parses nothing but the data a client asks
// to have signed, through package protocol, and verifies nothing: the host
// key's proof in a session binding is the agent's to check before the
// binding becomes a fact here.
//
// The rules, in the order they apply, from docs/design.md "Policy, and the
// decision the agent makes":
//
//  1. A connection bound for forwarding sees no key and signs nothing.
//  2. A connection on which a session binding was refused sees no key and
//     signs nothing.
//  3. A key is listed to an unbound connection when its policy allows
//     anything at all, and to a connection bound for authentication when a
//     destination of the policy carries the bound host key.
//  4. On a connection bound for authentication, the data must be a
//     public-key user-authentication request for this key, with the bound
//     session identifier, for a user a destination with the bound host key
//     allows; and the peer must be one the policy names.
//  5. On an unbound connection, the data must be an SSHSIG request in a
//     namespace the policy allows; and the peer must be one the policy
//     names. A user-authentication request on an unbound connection is
//     refused.
package policy
