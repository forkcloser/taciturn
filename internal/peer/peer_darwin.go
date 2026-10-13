//go:build darwin && cgo

package peer

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libproc.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// taciturn_peer_token reads the peer's audit token off the socket.
static int taciturn_peer_token(int fd, audit_token_t *token) {
	socklen_t length = sizeof *token;
	return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, token, &length);
}

// taciturn_code is the SecCode of the process the audit token names.
static SecCodeRef taciturn_code(const audit_token_t *token) {
	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, sizeof *token);
	CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attributes, kSecGuestAttributeAudit, data);
	SecCodeRef code = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
	CFRelease(attributes);
	CFRelease(data);
	return status == errSecSuccess ? code : NULL;
}

// taciturn_code_path copies the code's path into buf.
static int taciturn_code_path(SecCodeRef code, char *buf, size_t length) {
	CFURLRef url = NULL;
	if (SecCodeCopyPath(code, kSecCSDefaultFlags, &url) != errSecSuccess || url == NULL) {
		return -1;
	}
	Boolean ok = CFURLGetFileSystemRepresentation(url, true, (UInt8 *)buf, length);
	CFRelease(url);
	return ok ? 0 : -1;
}

// taciturn_code_valid says the code matches its signature.
static int taciturn_code_valid(SecCodeRef code) {
	return SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL) == errSecSuccess;
}

// taciturn_code_info copies the signing identifier and the cdhash, as hex.
static void taciturn_code_info(SecCodeRef code, char *identifier, size_t id_length, char *cdhash, size_t hash_length) {
	identifier[0] = 0;
	cdhash[0] = 0;
	CFDictionaryRef info = NULL;
	if (SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSDefaultFlags, &info) != errSecSuccess || info == NULL) {
		return;
	}
	CFStringRef id = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if (id != NULL) {
		CFStringGetCString(id, identifier, id_length, kCFStringEncodingUTF8);
	}
	CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
	if (unique != NULL) {
		const UInt8 *bytes = CFDataGetBytePtr(unique);
		CFIndex n = CFDataGetLength(unique);
		static const char hex[] = "0123456789abcdef";
		size_t out = 0;
		for (CFIndex i = 0; i < n && out + 2 < hash_length; i++) {
			cdhash[out++] = hex[bytes[i] >> 4];
			cdhash[out++] = hex[bytes[i] & 15];
		}
		cdhash[out] = 0;
	}
	CFRelease(info);
}

// taciturn_code_satisfies evaluates a requirement against the code:
// 1 satisfied, 0 not, -1 the requirement does not parse. A C string
// that is not UTF-8 makes no CFString, and is no requirement either.
static int taciturn_code_satisfies(SecCodeRef code, const char *requirement) {
	CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
	if (text == NULL) {
		return -1;
	}
	SecRequirementRef req = NULL;
	OSStatus status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &req);
	CFRelease(text);
	if (status != errSecSuccess || req == NULL) {
		return -1;
	}
	status = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(req);
	return status == errSecSuccess;
}

// taciturn_requirement_parses says whether the framework reads the text as
// a requirement: 1 yes, 0 no. No code is involved. Bytes that are not UTF-8
// make no CFString, and are no requirement.
static int taciturn_requirement_parses(const char *requirement) {
	CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
	if (text == NULL) {
		return 0;
	}
	SecRequirementRef req = NULL;
	OSStatus status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &req);
	CFRelease(text);
	if (status != errSecSuccess || req == NULL) {
		return 0;
	}
	CFRelease(req);
	return 1;
}

static int taciturn_pid_path(int pid, char *buf, size_t length) {
	return proc_pidpath(pid, buf, (uint32_t)length) > 0 ? 0 : -1;
}
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// codeHandle is the framework's reference to the peer's code, with the
// requirements already evaluated on it.
type codeHandle struct {
	mu        sync.Mutex
	ref       C.SecCodeRef
	satisfied map[string]bool
}

const pathBufferSize = 4096

// Identify reads the peer of a unix socket connection. The peer must run
// as this process's user, or the answer is ErrForeign and nothing else is
// read.
func Identify(conn *net.UnixConn) (*Identity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("peer: %w", ErrUnavailable)
	}

	var (
		identity *Identity
		ctrlErr  error
	)

	err = raw.Control(func(descriptor uintptr) { identity, ctrlErr = readPeer(int(descriptor)) })
	if err != nil {
		return nil, fmt.Errorf("peer: %w", ErrUnavailable)
	}

	if ctrlErr != nil {
		return nil, ctrlErr
	}

	if identity == nil {
		return nil, fmt.Errorf("peer: %w", ErrUnavailable)
	}

	return identity, nil
}

func readPeer(descriptor int) (*Identity, error) {
	cred, err := unix.GetsockoptXucred(descriptor, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("peer credentials: %w", ErrUnavailable)
	}

	if cred.Uid != uint32(os.Geteuid()) { // #nosec G115 -- a uid is non-negative
		return nil, fmt.Errorf("uid %d: %w", cred.Uid, ErrForeign)
	}

	pid, err := unix.GetsockoptInt(descriptor, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return nil, fmt.Errorf("peer pid: %w", ErrUnavailable)
	}

	var token C.audit_token_t
	if C.taciturn_peer_token(C.int(descriptor), &token) != 0 {
		return nil, fmt.Errorf("peer audit token: %w", ErrUnavailable)
	}

	code := C.taciturn_code(&token)
	if code == 0 {
		return nil, fmt.Errorf("peer code: %w", ErrUnavailable)
	}

	identity := &Identity{PID: pid, UID: cred.Uid}
	identity.code.ref = code
	identity.code.satisfied = map[string]bool{}

	var buf [pathBufferSize]C.char
	if C.taciturn_code_path(code, &buf[0], pathBufferSize) == 0 {
		identity.Path = C.GoString(&buf[0])
	}

	identity.ValidSignature = C.taciturn_code_valid(code) != 0

	var (
		id   [pathBufferSize]C.char
		hash [pathBufferSize]C.char
	)

	C.taciturn_code_info(code, &id[0], pathBufferSize, &hash[0], pathBufferSize)
	identity.Identifier = C.GoString(&id[0])
	identity.CDHash = C.GoString(&hash[0])
	identity.Parents = parents(pid)

	return identity, nil
}

// parents walks the process table up from pid, best effort and bounded.
func parents(pid int) []Process {
	var chain []Process

	for range MaxParents {
		info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			break
		}

		parent := int(info.Eproc.Ppid)
		if parent <= 1 {
			break
		}

		entry := Process{PID: parent}

		var buf [pathBufferSize]C.char
		if C.taciturn_pid_path(C.int(parent), &buf[0], pathBufferSize) == 0 {
			entry.Path = C.GoString(&buf[0])
		}

		chain = append(chain, entry)
		pid = parent
	}

	return chain
}

// Satisfies evaluates a code-signing requirement against the peer. A
// requirement the framework does not parse is ErrInvalid.
func (i *Identity) Satisfies(requirement string) (bool, error) {
	i.code.mu.Lock()
	defer i.code.mu.Unlock()

	if i.code.ref == 0 {
		return false, fmt.Errorf("peer code released: %w", ErrUnavailable)
	}

	if ok, seen := i.code.satisfied[requirement]; seen {
		return ok, nil
	}

	text := C.CString(requirement)
	defer C.free(unsafe.Pointer(text))

	switch C.taciturn_code_satisfies(i.code.ref, text) {
	case 1:
		i.code.satisfied[requirement] = true

		return true, nil
	case 0:
		i.code.satisfied[requirement] = false

		return false, nil
	default:
		return false, fmt.Errorf("requirement %q: %w", requirement, ErrInvalid)
	}
}

// ValidRequirement says whether the framework parses the text as a code
// requirement, without any code to evaluate it on: ErrInvalid when it does
// not. The agent treats an unparsable entry as unsatisfied, so this is
// what lets a policy edit refuse a typo instead of storing it.
func ValidRequirement(requirement string) error {
	text := C.CString(requirement)
	defer C.free(unsafe.Pointer(text))

	if C.taciturn_requirement_parses(text) != 1 {
		return fmt.Errorf("requirement %q: %w", requirement, ErrInvalid)
	}

	return nil
}

// Close releases the framework's reference. Closing twice is harmless.
func (i *Identity) Close() {
	i.code.mu.Lock()
	defer i.code.mu.Unlock()

	if i.code.ref != 0 {
		C.CFRelease(C.CFTypeRef(i.code.ref))
		i.code.ref = 0
	}
}
