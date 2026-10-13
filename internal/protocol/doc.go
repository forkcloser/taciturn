// Package protocol is the ssh-agent wire protocol as RFC 9987 and OpenSSH's
// PROTOCOL.agent define it: the framing, the requests an agent receives,
// the responses it sends, and the two shapes of data a client asks to have
// signed, a public-key user-authentication request (RFC 4252 section 7) and
// an SSHSIG signature request (OpenSSH PROTOCOL.sshsig).
//
// Every decoder is strict: a field that overruns its buffer, a length that
// claims more than is there, a byte left over after the last field, or a
// constant that is not what the format fixes is ErrInvalid. Nothing is
// decoded that the agent does not act on.
//
// Limits, each reported as ErrTooLarge: a message of more than MaxMessage
// bytes, a session identifier of more than MaxSessionID bytes.
package protocol
