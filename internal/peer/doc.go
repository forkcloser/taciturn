// Package peer says who is on the other end of a unix socket connection:
// the process's uid and pid from the socket's peer credentials, and, from
// its audit token, the executable path and code signature the kernel
// vouches for, which no process can forge and no pid reuse can confuse.
//
// Identify answers for the connection's immediate peer, the process that
// called connect: ssh, ssh-keygen, or something else. The chain of parents
// is read best effort from the process table for the log; nothing decides
// on it, since a parent can exit or be reused while the child lives.
//
// A code-signing requirement, in Apple's requirement language, is
// evaluated against the peer's code with Satisfies; the result is the
// framework's and is cached for the connection. A peer whose uid is not
// this process's is ErrForeign; a connection whose peer cannot be read is
// ErrUnavailable.
package peer
