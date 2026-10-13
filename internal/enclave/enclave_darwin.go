//go:build darwin && cgo

package enclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

// taciturn_error carries a CFError out of a call: its code and its text.
typedef struct {
	long code;
	char message[256];
} taciturn_error;

static void taciturn_capture(CFErrorRef err, taciturn_error *out) {
	out->code = 0;
	out->message[0] = 0;
	if (err == NULL) {
		return;
	}
	out->code = CFErrorGetCode(err);
	CFStringRef description = CFErrorCopyDescription(err);
	if (description != NULL) {
		CFStringGetCString(description, out->message, sizeof out->message, kCFStringEncodingUTF8);
		CFRelease(description);
	}
	CFRelease(err);
}

static CFMutableDictionaryRef taciturn_dictionary(void) {
	return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

// taciturn_generate makes a non-permanent P-256 key in the enclave with
// private-key-usage access control in the given class.
static SecKeyRef taciturn_generate(int after_first_unlock, taciturn_error *e) {
	CFErrorRef err = NULL;
	CFTypeRef protection = after_first_unlock
		? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		: kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
	SecAccessControlRef access = SecAccessControlCreateWithFlags(NULL, protection, kSecAccessControlPrivateKeyUsage, &err);
	if (access == NULL) {
		taciturn_capture(err, e);
		return NULL;
	}

	CFMutableDictionaryRef private_attributes = taciturn_dictionary();
	CFDictionarySetValue(private_attributes, kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(private_attributes, kSecAttrAccessControl, access);

	int bits = 256;
	CFNumberRef size = CFNumberCreate(NULL, kCFNumberIntType, &bits);
	CFMutableDictionaryRef attributes = taciturn_dictionary();
	CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, size);
	CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attributes, kSecPrivateKeyAttrs, private_attributes);

	SecKeyRef key = SecKeyCreateRandomKey(attributes, &err);
	taciturn_capture(err, e);

	CFRelease(attributes);
	CFRelease(size);
	CFRelease(private_attributes);
	CFRelease(access);
	return key;
}

// taciturn_blob is the enclave's wrapped copy of the key: the
// kSecAttrTokenOID attribute, whose name the public headers do not export.
static CFDataRef taciturn_blob(SecKeyRef key) {
	CFDictionaryRef attributes = SecKeyCopyAttributes(key);
	if (attributes == NULL) {
		return NULL;
	}
	CFDataRef toid = CFDictionaryGetValue(attributes, CFSTR("toid"));
	if (toid != NULL) {
		CFRetain(toid);
	}
	CFRelease(attributes);
	return toid;
}

// taciturn_load rebuilds a key from its blob. The blob goes in the
// attributes as kSecAttrTokenOID: SecKeyCreateWithData ignores its data
// argument for a token key and generates a fresh key when the attribute is
// absent (docs/design.md F4).
static SecKeyRef taciturn_load(const void *blob, size_t length, taciturn_error *e) {
	CFErrorRef err = NULL;
	CFDataRef toid = CFDataCreate(NULL, blob, length);
	CFDataRef empty = CFDataCreate(NULL, NULL, 0);
	CFMutableDictionaryRef attributes = taciturn_dictionary();
	CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attributes, CFSTR("toid"), toid);
	CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

	SecKeyRef key = SecKeyCreateWithData(empty, attributes, &err);
	taciturn_capture(err, e);

	CFRelease(attributes);
	CFRelease(empty);
	CFRelease(toid);
	return key;
}

// taciturn_public is the public key as an uncompressed point.
static CFDataRef taciturn_public(SecKeyRef key, taciturn_error *e) {
	CFErrorRef err = NULL;
	SecKeyRef public = SecKeyCopyPublicKey(key);
	if (public == NULL) {
		e->code = 0;
		strncpy(e->message, "no public key", sizeof e->message);
		return NULL;
	}
	CFDataRef point = SecKeyCopyExternalRepresentation(public, &err);
	taciturn_capture(err, e);
	CFRelease(public);
	return point;
}

// taciturn_sign is an ECDSA signature over SHA-256 of the message, DER.
static CFDataRef taciturn_sign(SecKeyRef key, const void *message, size_t length, taciturn_error *e) {
	CFErrorRef err = NULL;
	CFDataRef data = CFDataCreate(NULL, message, length);
	CFDataRef signature = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data, &err);
	taciturn_capture(err, e);
	CFRelease(data);
	return signature;
}
*/
import "C"

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"unsafe"
)

// Available says whether this process can reach the enclave: it makes a
// key and discards it. False from a sandbox, a virtual machine, or a
// process the framework will not serve.
func Available() bool {
	key, err := Generate(ClassAfterFirstUnlock)
	if err != nil {
		return false
	}

	key.Close()

	return true
}

// Generate makes a new key in the enclave with the class.
func Generate(class Class) (*Key, error) {
	var afterFirstUnlock C.int

	switch class {
	case ClassAfterFirstUnlock:
		afterFirstUnlock = 1
	case ClassWhenUnlocked:
		afterFirstUnlock = 0
	default:
		return nil, fmt.Errorf("class %d: %w", class, ErrInvalid)
	}

	var cerr C.taciturn_error

	ref := C.taciturn_generate(afterFirstUnlock, &cerr)
	if ref == 0 {
		return nil, classify("generating key", cerr)
	}

	key, err := wrap(ref)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Load rebuilds a key from its blob and checks it against the public key
// stored beside the blob. A blob the enclave rejects is ErrInvalid; a key
// whose public half is not public is ErrMismatch, and no such key is
// returned.
func Load(blob, public []byte) (*Key, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob: %w", ErrInvalid)
	}

	if len(public) != PointSize || public[0] != 0x04 {
		return nil, fmt.Errorf("public key of %d bytes: %w", len(public), ErrInvalid)
	}

	var cerr C.taciturn_error

	ref := C.taciturn_load(unsafe.Pointer(&blob[0]), C.size_t(len(blob)), &cerr)
	if ref == 0 {
		return nil, classify("loading key", cerr)
	}

	key, err := wrap(ref)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(key.public, public) {
		key.Close()

		return nil, ErrMismatch
	}

	if !bytes.Equal(key.blob, blob) {
		// The enclave re-encoded the blob it was given: the key is the
		// right one (its public half matched), and the stored blob stays
		// the one to keep, so the key carries it.
		key.blob = append([]byte(nil), blob...)
	}

	return key, nil
}

// wrap takes ownership of a reference and reads its blob and public key.
func wrap(ref C.SecKeyRef) (*Key, error) {
	key := &Key{handle: &keyHandle{ref: ref}}
	runtime.AddCleanup(key, (*keyHandle).release, key.handle)

	blob := C.taciturn_blob(ref)
	if blob == 0 {
		key.Close()

		return nil, fmt.Errorf("key without a wrapped form: %w", ErrInternal)
	}

	key.blob = takeData(blob)

	var cerr C.taciturn_error

	public := C.taciturn_public(ref, &cerr)
	if public == 0 {
		key.Close()

		return nil, classify("reading public key", cerr)
	}

	key.public = takeData(public)
	if len(key.public) != PointSize || key.public[0] != 0x04 {
		key.Close()

		return nil, fmt.Errorf("public key of %d bytes: %w", len(key.public), ErrInternal)
	}

	return key, nil
}

// Sign signs SHA-256 of the message with the key.
func (k *Key) Sign(message []byte) (sigR, sigS *big.Int, err error) {
	k.handle.mu.Lock()
	defer k.handle.mu.Unlock()

	if k.handle.ref == 0 {
		return nil, nil, fmt.Errorf("key is closed: %w", ErrInvalid)
	}

	var cerr C.taciturn_error

	var ptr unsafe.Pointer
	if len(message) > 0 {
		ptr = unsafe.Pointer(&message[0])
	}

	der := C.taciturn_sign(k.handle.ref, ptr, C.size_t(len(message)), &cerr)
	if der == 0 {
		return nil, nil, classify("signing", cerr)
	}

	return parseDER(takeData(der))
}

// takeData copies a CFData's bytes out and releases it.
func takeData(data C.CFDataRef) []byte {
	out := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data)))
	C.CFRelease(C.CFTypeRef(data))

	return out
}

// ecdsaSignature is the DER shape of an ECDSA signature, RFC 3279.
type ecdsaSignature struct {
	R, S *big.Int
}

func parseDER(der []byte) (sigR, sigS *big.Int, err error) {
	var sig ecdsaSignature

	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, nil, fmt.Errorf("signature is not DER ECDSA: %w", ErrInternal)
	}

	return sig.R, sig.S, nil
}

// The OSStatus values the framework reports for the cases a caller acts on
// (Security/SecBase.h). -26276 is what SecKeyCreateRandomKey answers when
// the enclave cannot be reached ("Failed to generate keypair"), not a
// named constant in the header.
const (
	osStatusMissingEntitlement    = -34018
	osStatusInteractionNotAllowed = -25308
	osStatusAuthFailed            = -25293
	osStatusNotAvailable          = -25291
	osStatusEnclaveUnreachable    = -26276
	osStatusDecode                = -26275
	osStatusParam                 = -50
)

func classify(operation string, cerr C.taciturn_error) error {
	code := int(cerr.code)
	message := C.GoString(&cerr.message[0])

	var sentinel error

	switch code {
	case osStatusMissingEntitlement, osStatusNotAvailable, osStatusEnclaveUnreachable:
		sentinel = ErrUnavailable
	case osStatusInteractionNotAllowed, osStatusAuthFailed:
		sentinel = ErrRefused
	case osStatusDecode, osStatusParam:
		sentinel = ErrInvalid
	default:
		sentinel = ErrInternal
	}

	if errors.Is(sentinel, ErrInternal) {
		return fmt.Errorf("%s: OSStatus %d: %s: %w", operation, code, message, sentinel)
	}

	return fmt.Errorf("%s: OSStatus %d: %w", operation, code, sentinel)
}

// keyHandle holds the framework's reference to a key and releases it once,
// whether Close, the collector's cleanup, or both ask.
type keyHandle struct {
	mu  sync.Mutex
	ref C.SecKeyRef
}

func (h *keyHandle) release() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ref != 0 {
		C.CFRelease(C.CFTypeRef(h.ref))
		h.ref = 0
	}
}
