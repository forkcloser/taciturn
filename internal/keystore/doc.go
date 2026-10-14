// Package keystore keeps the agent's records on disk: for each key, what
// the key is and what it may do. The key itself lives in the keychain
// (package enclave), under the key's fingerprint as its label.
//
// The store is one directory, created private (0700), holding one file per
// key named by its fingerprint: <id>.json, the Record, rewritten atomically
// whenever the policy or the lifecycle changes, private (0600). Writers
// hold an advisory lock on the directory's lock file; readers need none,
// since a record is replaced by rename.
//
// A v0.1 store also holds <id>.blob beside each record, the enclave's
// wrapped key from before keys lived in the keychain. The store reads such
// a blob for `key import` only (LegacyBlob) and deletes it once the key is
// in the keychain (RemoveLegacyBlob); LegacyBlobs lists the keys still to
// move, which doctor reports.
//
// Every read checks what it reads: a record whose fingerprint is not the
// fingerprint of its public key, a blob without its record, or JSON that
// does not decode is ErrCorrupt, and List fails on the first such entry
// rather than serve the rest. A directory or a file readable by anyone but
// the owner is ErrInsecure, and the store refuses to open. A name or a
// fingerprint that is not well-formed is ErrInvalid; a key or a name
// already present is ErrExists; one absent is ErrNotFound. A failure of the
// filesystem underneath is returned as it came.
//
// Limits: a name is 1 to MaxNameLength characters of letters, digits, '.',
// '_', '@' and '-', not starting with '.' or '-'; a v0.1 blob is at most
// MaxBlob bytes (an enclave blob is a few hundred).
package keystore
