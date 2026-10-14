//go:build darwin && cgo

package enclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

// taciturn_error carries a CFError or an OSStatus out of a call: its code
// and its text.
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

static void taciturn_status(OSStatus status, taciturn_error *out) {
	out->code = status;
	out->message[0] = 0;
	if (status == errSecSuccess) {
		return;
	}
	CFStringRef text = SecCopyErrorMessageString(status, NULL);
	if (text != NULL) {
		CFStringGetCString(text, out->message, sizeof out->message, kCFStringEncodingUTF8);
		CFRelease(text);
	}
}

static CFMutableDictionaryRef taciturn_dictionary(void) {
	return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static CFStringRef taciturn_string(const char *text) {
	return CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
}

// taciturn_access_groups writes this process's own keychain-access-groups
// entitlement into buf, one entry per line: the count of entries written,
// 0 when the process carries no such entitlement (a build outside the
// signed bundle, docs/design.md v0.2).
static int taciturn_access_groups(char *buf, size_t length) {
	buf[0] = 0;
	SecTaskRef task = SecTaskCreateFromSelf(NULL);
	if (task == NULL) {
		return 0;
	}
	CFErrorRef err = NULL;
	CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("keychain-access-groups"), &err);
	CFRelease(task);
	if (err != NULL) {
		CFRelease(err);
	}
	if (value == NULL) {
		return 0;
	}
	int written = 0;
	size_t used = 0;
	if (CFGetTypeID(value) == CFArrayGetTypeID()) {
		CFIndex count = CFArrayGetCount((CFArrayRef)value);
		for (CFIndex i = 0; i < count && used + 2 < length; i++) {
			CFTypeRef entry = CFArrayGetValueAtIndex((CFArrayRef)value, i);
			if (entry == NULL || CFGetTypeID(entry) != CFStringGetTypeID()) {
				continue;
			}
			if (!CFStringGetCString((CFStringRef)entry, buf + used, length - used, kCFStringEncodingUTF8)) {
				break;
			}
			used += strlen(buf + used);
			buf[used++] = '\n';
			buf[used] = 0;
			written++;
		}
	}
	CFRelease(value);
	return written;
}

// taciturn_generate makes a transient P-256 key in the enclave with
// private-key-usage access control in the given class. Transient: the
// keychain holds nothing until taciturn_store adds it.
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
// It stays inside this package (docs/design.md F16).
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

// taciturn_load rebuilds a transient key from its blob, for an import of a
// v0.1 key. The blob goes in the attributes as kSecAttrTokenOID:
// SecKeyCreateWithData ignores its data argument for a token key and
// generates a fresh key when the attribute is absent (docs/design.md F4).
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

// taciturn_store adds the key to the data-protection keychain under the
// access group, labelled, as a permanent item (docs/design.md F13, F17).
static OSStatus taciturn_store(SecKeyRef key, const char *label, const char *group) {
	CFStringRef cflabel = taciturn_string(label);
	CFStringRef cfgroup = taciturn_string(group);
	CFDataRef tag = CFDataCreate(NULL, (const UInt8 *)label, strlen(label));
	CFMutableDictionaryRef attributes = taciturn_dictionary();
	CFDictionarySetValue(attributes, kSecClass, kSecClassKey);
	CFDictionarySetValue(attributes, kSecValueRef, key);
	CFDictionarySetValue(attributes, kSecAttrLabel, cflabel);
	CFDictionarySetValue(attributes, kSecAttrApplicationTag, tag);
	CFDictionarySetValue(attributes, kSecAttrAccessGroup, cfgroup);
	CFDictionarySetValue(attributes, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	OSStatus status = SecItemAdd(attributes, NULL);
	CFRelease(attributes);
	CFRelease(tag);
	CFRelease(cfgroup);
	CFRelease(cflabel);
	return status;
}

// taciturn_lookup finds the private enclave key labelled so in the
// data-protection keychain, which the framework scopes to the access
// groups this process is entitled to.
static SecKeyRef taciturn_lookup(const char *label, taciturn_error *e) {
	CFStringRef cflabel = taciturn_string(label);
	CFMutableDictionaryRef query = taciturn_dictionary();
	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
	CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(query, kSecAttrLabel, cflabel);
	CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	CFTypeRef ref = NULL;
	OSStatus status = SecItemCopyMatching(query, &ref);
	taciturn_status(status, e);
	CFRelease(query);
	CFRelease(cflabel);
	return status == errSecSuccess ? (SecKeyRef)ref : NULL;
}

// taciturn_delete removes every key item labelled so from the
// data-protection keychain.
static OSStatus taciturn_delete(const char *label) {
	CFStringRef cflabel = taciturn_string(label);
	CFMutableDictionaryRef query = taciturn_dictionary();
	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrLabel, cflabel);
	CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	CFRelease(cflabel);
	return status;
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
	"strings"
	"sync"
	"unsafe"
)

const accessGroupBuffer = 4096

// AccessGroup is the keychain access group this process stores keys
// under: the entry of its own keychain-access-groups entitlement that ends
// in AccessGroupSuffix, whatever else the entitlement lists and in whatever
// order (docs/design.md, decision 16). A process without one, which is any
// build run outside the signed bundle, gets ErrUnavailable, and no key can
// be stored, loaded or deleted by it.
func AccessGroup() (string, error) {
	buf := make([]byte, accessGroupBuffer)
	if C.taciturn_access_groups((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) < 1 {
		return "", fmt.Errorf(
			"no keychain-access-groups entitlement, not running from the signed bundle: %w",
			ErrUnavailable,
		)
	}

	for group := range strings.SplitSeq(C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), "\n") {
		if strings.HasSuffix(group, "."+AccessGroupSuffix) {
			return group, nil
		}
	}

	return "", fmt.Errorf("no keychain access group ends in %s: %w", AccessGroupSuffix, ErrUnavailable)
}

// Available says whether this process can reach the enclave: it makes a
// transient key and discards it. False from a sandbox, a virtual machine,
// or a process the framework will not serve. It says nothing about the
// keychain; AccessGroup does.
func Available() bool {
	key, err := Generate(ClassAfterFirstUnlock)
	if err != nil {
		return false
	}

	key.Close()

	return true
}

// Generate makes a new transient key in the enclave with the class. It
// exists in this process alone until Store puts it in the keychain.
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

	return wrap(ref)
}

// Store puts the key in the data-protection keychain under this process's
// access group, labelled: from then on Load finds it by the label in any
// process entitled to the group. A label already taken is ErrExists.
func (k *Key) Store(label string) error {
	err := ValidateLabel(label)
	if err != nil {
		return err
	}

	group, err := AccessGroup()
	if err != nil {
		return err
	}

	k.handle.mu.Lock()
	defer k.handle.mu.Unlock()

	if k.handle.ref == 0 {
		return fmt.Errorf("key is closed: %w", ErrInvalid)
	}

	clabel, cgroup := C.CString(label), C.CString(group)
	defer C.free(unsafe.Pointer(clabel))
	defer C.free(unsafe.Pointer(cgroup))

	// The keychain tells keys apart by their own attributes, not by the
	// label: two different keys under one label are two items to it (seen
	// on the hardware, 2026-10-13). The label is the agent's name for the
	// key, so it is unique here.
	var cerr C.taciturn_error

	if taken := C.taciturn_lookup(clabel, &cerr); taken != 0 {
		C.CFRelease(C.CFTypeRef(taken))

		return fmt.Errorf("keychain item %q: %w", label, ErrExists)
	}

	status := C.taciturn_store(k.handle.ref, clabel, cgroup)
	if status == C.errSecDuplicateItem {
		return fmt.Errorf("keychain item %q: %w", label, ErrExists)
	}

	if status != C.errSecSuccess {
		C.taciturn_status(status, &cerr)

		return classify("storing key", cerr)
	}

	return nil
}

// Load finds the key labelled so in the keychain and checks it against the
// public key the caller stored beside the label: a key whose public half
// is not public is ErrMismatch, and no such key is returned; no key under
// the label is ErrNotFound.
func Load(label string, public []byte) (*Key, error) {
	err := ValidateLabel(label)
	if err != nil {
		return nil, err
	}

	err = validatePoint(public)
	if err != nil {
		return nil, err
	}

	_, err = AccessGroup()
	if err != nil {
		return nil, err
	}

	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(clabel))

	var cerr C.taciturn_error

	ref := C.taciturn_lookup(clabel, &cerr)
	if ref == 0 {
		if cerr.code == C.errSecItemNotFound {
			return nil, fmt.Errorf("keychain item %q: %w", label, ErrNotFound)
		}

		return nil, classify("looking key up", cerr)
	}

	key, err := wrap(ref)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(key.public, public) {
		key.Close()

		return nil, ErrMismatch
	}

	return key, nil
}

// Import rebuilds a v0.1 key from its wrapped blob, checks it against the
// public key, and stores it in the keychain under the label
// (docs/design.md F17). The returned key is open.
func Import(blob, public []byte, label string) (*Key, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob: %w", ErrInvalid)
	}

	err := validatePoint(public)
	if err != nil {
		return nil, err
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

	err = key.Store(label)
	if err != nil {
		key.Close()

		return nil, err
	}

	return key, nil
}

// Delete removes the key labelled so from the keychain. No key under the
// label is ErrNotFound.
func Delete(label string) error {
	err := ValidateLabel(label)
	if err != nil {
		return err
	}

	_, err = AccessGroup()
	if err != nil {
		return err
	}

	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(clabel))

	status := C.taciturn_delete(clabel)
	if status == C.errSecItemNotFound {
		return fmt.Errorf("keychain item %q: %w", label, ErrNotFound)
	}

	if status != C.errSecSuccess {
		var cerr C.taciturn_error

		C.taciturn_status(status, &cerr)

		return classify("deleting key", cerr)
	}

	return nil
}

func validatePoint(public []byte) error {
	if len(public) != PointSize || public[0] != 0x04 {
		return fmt.Errorf("public key of %d bytes: %w", len(public), ErrInvalid)
	}

	return nil
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
