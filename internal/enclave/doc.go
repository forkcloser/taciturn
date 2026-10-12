// Package enclave is the Secure Enclave: it makes P-256 signing keys there,
// reloads them from the wrapped form the enclave hands back, and signs with
// them. Nothing else touches Security.framework.
//
// A key made here is never written to the keychain (kSecAttrIsPermanent is
// false): what persists is Blob, the enclave's own wrapped copy of the key,
// readable as the key's kSecAttrTokenOID attribute, which only this
// machine's enclave can unwrap. A caller stores it and later hands it to
// Load with the public key it stored beside it: Load refuses with
// ErrMismatch when the enclave answers with another key, because
// SecKeyCreateWithData silently makes a new key when the attribute it needs
// is missing (docs/design.md F4), and no signature is ever made with a key
// that was not checked against its public half.
//
// The access class a key is made with travels inside the blob and decides
// when the enclave agrees to sign: ClassAfterFirstUnlock from the first
// unlock after boot until the next boot, ClassWhenUnlocked only while the
// session is unlocked. A refusal by the enclave is ErrRefused; an enclave
// that cannot be reached at all, from a sandbox, a virtual machine or a
// process without a code signature, is ErrUnavailable; a blob the enclave
// does not accept is ErrInvalid.
//
// Signing is ECDSA over SHA-256 of the message, the framework hashing and
// the enclave signing; the result is the pair (r, s), never DER.
package enclave
