// Package keystore keeps the agent's keys on disk: for each key, the
// enclave-wrapped blob the enclave hands back for it and a record of what
// the key is and what it may do.
//
// The store is one directory, created private (0700), holding two files per
// key named by its fingerprint: <id>.blob, the wrapped key, written once and
// never rewritten; and <id>.json, the Record, rewritten atomically whenever
// the policy or the lifecycle changes. Both are private (0600). Writers
// hold an advisory lock on the directory's lock file; readers need none,
// since a record is replaced by rename and a blob never changes.
//
// Every read checks what it reads: a record whose fingerprint is not the
// fingerprint of its public key, a record without its blob, a blob without
// its record, or JSON that does not decode is ErrCorrupt, and List fails on
// the first such entry rather than serve the rest. A directory or a file
// readable by anyone but the owner is ErrInsecure, and the store refuses to
// open. A name or a fingerprint that is not well-formed is ErrInvalid; a
// key or a name already present is ErrExists; one absent is ErrNotFound. A
// failure of the filesystem underneath is returned as it came.
//
// Limits: a name is 1 to MaxNameLength characters of letters, digits, '.',
// '_', '@' and '-', not starting with '.' or '-'; a blob is at most MaxBlob
// bytes (an enclave blob is a few hundred).
package keystore
