// Package enclave is the Secure Enclave and the keychain item that names a
// key in it: it makes P-256 signing keys there, stores them in the
// data-protection keychain, finds them again and signs with them. Nothing
// else touches Security.framework's keys.
//
// Generate makes a key that exists in this process alone. Store puts it in
// the keychain under a label, in this process's keychain access group, the
// entry of its own keychain-access-groups entitlement that ends in
// AccessGroupSuffix; from then on Load finds it by the label, in any
// process entitled to the group and in no other, and Delete removes it. A
// process without the entitlement, which is any build run outside the
// signed bundle, gets ErrUnavailable from all three.
//
// The label is the caller's name for the key and proves nothing: the
// keychain keeps two different keys under one label as two items. So Store
// refuses a label already taken, and Load takes the public key the caller
// stored beside the label and answers ErrMismatch when the keychain's key
// is another: no signature is ever made with a key that was not checked
// against its public half.
//
// Import is for a key from before keys lived in the keychain, kept as the
// enclave's wrapped copy of it: it rebuilds the key, checks it the same
// way, since rebuilding has a trap that makes a new key silently
// (docs/design.md F4), and stores it. No wrapped copy leaves this package:
// any process that holds one can have the enclave sign with it
// (docs/design.md F16).
//
// The access class a key is made with decides when the enclave agrees to
// sign: ClassAfterFirstUnlock from the first unlock after boot until the
// next boot, ClassWhenUnlocked only while the session is unlocked. A
// refusal by the enclave is ErrRefused; an enclave that cannot be reached
// at all, from a sandbox, a virtual machine or a process the framework
// will not serve, is ErrUnavailable; an argument the package refuses is
// ErrInvalid, whether or not there is an enclave to ask.
//
// Signing is ECDSA over SHA-256 of the message, the framework hashing and
// the enclave signing; the result is the pair (r, s), never DER.
package enclave
