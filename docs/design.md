# taciturn — an ssh-agent for Secure Enclave keys, for unattended sessions

Status: **decided by Apostasie, 2026-10-12** (the record is the last section; cgo over
purego was decided in the same conversation). Written that day by the Taciturn session.
Every fact below marked *(verified)* was checked on this machine that day (macAntaloop,
macOS 26.6.2, Apple Silicon, Xcode 27.0, Go 1.27.2); the scratch programs and their output
are in the appendix. v0.1 is implemented and in service; the section "v0.2: keys in the
data-protection keychain, in a signed bundle", decided 2026-10-13, amends decision 1 and
the distribution section and is the next implementation.

## Why

Today the bot's key (`closer-claudio`) lives in the Secure Enclave and is served by
[Secretive](https://github.com/maxgoedjen/secretive)'s agent, wired into the sessions by
`limen-install-agent` (farcloser/limen-install) as the book describes
(limen `book/identity.md`, "The bot's key" and "The bot's sandbox"). That works, and the
doctrine it implements is right: a hardware-bound, non-exportable key, no touch, the
rulesets as the veto. What is wrong is the tool around it:

- **It is a GUI application we do not build.** A Swift app with a menu bar, an XPC helper,
  notifications and a sandbox container, signed with someone else's Developer ID, updated
  on its own schedule, with the keychain as its database. It cannot be pinned, attested or
  reviewed the way everything else on the machine is.
- **It stops working when the screen locks.** Secretive creates every key as
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; the enclave refuses to sign a few seconds
  after the screen locks, even for keys with authentication off
  ([maxgoedjen/secretive#462](https://github.com/maxgoedjen/secretive/issues/462), the
  opt-in proposed in [#819](https://github.com/maxgoedjen/secretive/pull/819)). The sessions
  are meant to work unattended, which is exactly when the screen is locked; the book today
  tells them to leave the work ready and stop. That is a workaround for a tool limit, not a
  property anyone wanted.
- **It enforces nothing about what the key is used for.** Any process that reaches the
  socket gets a signature for anything: any host, any user, any sshsig namespace, through
  any forwarding. Secretive's session-binding code is present and disabled ("until forward
  enforcement is handled", `Agent.swift`). The agent protocol carries enough to do far
  better (below).
- **It cannot be inspected from a shell.** Listing keys, reading a key's settings, seeing
  who used a key and for what, happen in the app's window or not at all.

taciturn is the replacement: one static-looking Go binary, darwin/arm64 only, that is the
agent and the management CLI, keeps its keys in the Secure Enclave, runs as a user
LaunchAgent, and signs only what a per-key policy allows. The consumers are the Claude
sessions through their sandbox; the operator is Apostasie, from a shell.

### Goals

1. Private keys that never exist outside the Secure Enclave, usable without a touch, usable
   while the screen is locked when the key says so.
2. A signature only for what the key is allowed to do: a named destination (host key and
   user), a named sshsig namespace, never through forwarding, never for an unknown shape of
   data.
3. Every use recorded: which process, which key, which destination, allowed or refused.
4. A CLI to create, list, inspect, constrain, rotate, retire and delete keys, and to
   install the agent. Rotation of any signer, bot or human, cheap enough to be routine
   (P1, "Key rotation" below).
5. The fleet's standards: limen-onboarded, the book's testing shape, pinned and attested
   releases, minimal dependencies, nothing reinvented that primordium or `x/crypto` has.

### Non-goals

- Touch ID, Apple Watch or passcode gates. The book settled it: a reflexive tap is theater
  for the bot; the human's YubiKey keeps its touch. (The access-control flags exist and the
  design does not preclude adding `.userPresence` per key later; nothing in v1 uses it.)
- Replacing the human's agent (forkcloser/openssh's `org.forkcloser.ssh_agent`), the
  system agent, or `SSH_AUTH_SOCK` handling for humans. taciturn is pinned into the sessions
  by `IdentityAgent`, as Secretive is today.
- Smart cards, PKCS#11, FIDO, software keys, key import or export. The enclave has no
  import and no export; that is the point.
- Linux, Windows, Intel Macs.
- ML-DSA keys. macOS 26's enclave can hold them (CryptoKit `SecureEnclave.MLDSA65/87`,
  Secretive uses them), but GitHub does not accept them and the Security.framework C API
  does not expose them; revisit when both change.

## Facts the design rests on

Each item is the fact, then where it comes from.

**F1. The Secure Enclave signs ECDSA P-256 and nothing else usable here.** No ed25519, no
RSA. Our bot key is `ecdsa-sha2-nistp256` for that reason (identity.md, last paragraph).

**F2. Our own OpenSSH cannot use the key; Apple's can, and already does.**
forkcloser/openssh is built `--without-openssl` (`build.sh` line 160): no ECDSA at all, and
its `ssh_config` pins `PubkeyAcceptedAlgorithms` to ed25519 forms. The sessions therefore
already run Apple's `/usr/bin/ssh` (OpenSSH 10.3p1, LibreSSL, `ssh -Q key` lists
`ecdsa-sha2-nistp256`) through `core.sshCommand`, and Apple's `ssh-keygen` through the
signing wrapper, both with the agent socket pinned inside (`limen-install-agent`,
`merge_settings` and `install_helper`). taciturn changes nothing there: its clients are
Apple's `ssh` and `ssh-keygen`, by `IdentityAgent` and `SSH_AUTH_SOCK` inside the wrapper.
This is a standing conflict worth naming: the two sides have **no algorithm in common**.
The enclave signs P-256 only (ML-DSA-65/87 on macOS 26 is CryptoKit-only, GitHub does not
accept it, and OpenSSH's `ssh-mldsa44-ed25519` hybrid needs an ed25519 half the enclave
cannot hold); in OpenSSH every ECDSA type, `sk-ecdsa-sha2-nistp256@openssh.com` included,
is compiled only with libcrypto. The ways to make them meet, ranked: **(a)** build the
fork against LibreSSL, whose libcrypto it already compiles statically for libfido2, so
P-256 exists; the shipped config stays ed25519-only and the sessions' `core.sshCommand`
adds `-o PubkeyAcceptedAlgorithms=ecdsa-sha2-nistp256` (the smallest change, and what
Apple's ssh is; it reverses a stated stance of the fork, so it is the Forkcloser
Maintainer's and Apostasie's); **(b)** keep Apple's ssh for the bot, the status quo;
**(c)** a dedicated YubiKey for the bot (`ed25519-sk`, `-O no-touch-required`) served by
our own agent and ssh — hardware to buy and keep plugged in, a key handle file that is a
software artifact like the blob, and a different project for the policy layer. A software
ed25519 key is not an option: it loses the hardware-bound property the identity model
rests on. **Decided: (a)**, the fork gains P-256 and becomes the bot's only ssh; (b) is the
interim until it ships (decision 7). taciturn works with either. In flight the same day
(Forkcloser Maintainer, `claudio/20261012-p256`): libcrypto brings RSA into the binary as
well, since OpenSSH has no knob for ECDSA without RSA, and the shipped config keeps every
RSA form out of negotiation; the binaries are ad-hoc signed as `org.forkcloser.<name>`,
which proves no origin, so taciturn names them by path and logs the cdhash (F9).

**F3. A command-line tool can create and use enclave keys without the keychain and
without entitlements; the keychain path is closed to it.** *(verified)*
- A key stored *in* the keychain (`kSecAttrIsPermanent`) needs the data-protection keychain,
  which needs a `keychain-access-groups` entitlement authorised by a provisioning profile
  embedded in an `.app` bundle: a bare Mach-O cannot have one, and ad-hoc signing fails with
  `errSecMissingEntitlement` (-34018). Apostasie's only signing identity is an "Apple
  Development" certificate (`security find-identity`), which is for development builds, not
  distribution; a release built on CI has none. So: no keychain.
- `SecKeyCreateRandomKey` with `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`,
  `kSecAttrIsPermanent = false` and a `SecAccessControl` succeeds from an **ad-hoc signed**
  command-line binary (appendix, `se2 create`). The key's wrapped form is the
  `kSecAttrTokenOID` attribute (wire name `toid`, 324 bytes), readable with
  `SecKeyCopyAttributes`. It is byte-for-byte the same thing as CryptoKit's
  `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation`: a blob made by the C API loads
  in CryptoKit and verifies, and vice versa (appendix, `se load` / `se3`).
- The blob is useless off this machine: it is wrapped by this enclave's key and unwrapped
  only inside it. It is not key material, and copying it to another Mac yields nothing.
- `SecKeyCopyExternalRepresentation` refuses enclave keys ("export not implemented",
  `SecKey.m`); the blob is only reachable through the attribute.

**F4. Reloading a key has a trap that generates a new key silently.** *(verified)*
`SecKeyCreateWithData(data, attrs)` with the token id in `attrs` **ignores `data`** and calls
`SecKeyCreateCTKKey(attrs)` (Apple's `SecKey.m`); `SecCTKKey.m` then reads
`kSecAttrTokenOID` from the attributes and, when it is absent, runs "Generate new key". The
call succeeds, returns a different key, signs with it, and nothing fails until a verifier
rejects the signature (appendix, `se4` variants C and E; Apple forum reports say the same).
The correct reload passes the blob as the `kSecAttrTokenOID` attribute (`se4` A/B/D). The
enclave package must expose exactly one way to load a key, and its hardware test must
assert that the loaded public key equals the stored one before any signature is made.

**F5. The access class travels inside the blob.** *(verified)* A key created with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `.privateKeyUsage` reloads with
`SecAccessControl: cku;…` (class C, this device), from both the C and the CryptoKit blob
(appendix, `se5`). The class is a creation-time decision per key; nothing changes it later.

**F6. The enclave is unreachable from inside the Claude sandbox.** *(verified)* The same
binary fails `SecKeyCreateRandomKey` with `-26276` ("Failed to generate keypair") under the
sandbox and succeeds outside it; a software P-256 key succeeds in both. The agent must be an
unsandboxed process of the user (a LaunchAgent), and a session only ever reaches its socket.
This also means a sandboxed session that reads a key blob cannot use it.

**F7. Locked-screen behaviour follows the class.** *(verified)* Secretive's keys are
`WhenUnlockedThisDeviceOnly` and stop signing after the screen locks; keys created
`AfterFirstUnlockThisDeviceOnly` keep signing until the next boot
([secretive#819](https://github.com/maxgoedjen/secretive/pull/819)'s table;
[korev-sign](https://github.com/thiagosalvatore/korev/pull/263) does exactly this). Seen
on this machine the same afternoon, by accident of timing: with the screen locked,
Secretive's agent refused every signature ("agent refused operation"), the enclave
package's hardware tests generated, reloaded across two processes and signed with
`AfterFirstUnlock` keys, and a `WhenUnlocked` key could not even be *created*
(`SecKeyCreateRandomKey`, `OSStatus -25308`, `errSecInteractionNotAllowed`).

**F8. The agent protocol carries the destination, and Apple's ssh sends it.**
[RFC 9987](https://datatracker.ietf.org/doc/html/rfc9987) plus OpenSSH's `PROTOCOL.agent`:
- Before listing identities, `ssh` (8.9 and later; Apple's 10.3 included,
  `sshconnect2.c` `get_agent_identities`) sends the `session-bind@openssh.com` extension:
  the server's host key, the session identifier (the exchange hash), the host key's
  signature over it from the key exchange, and an `is_forwarding` flag. The agent verifies
  the signature, so the binding is proof of which server the connection is for, and
  records it for the life of the connection.
- A public-key userauth signature request signs `session_id ‖ SSH_MSG_USERAUTH_REQUEST ‖
  user ‖ "ssh-connection" ‖ "publickey" ‖ true ‖ pkalg ‖ pubkey` (RFC 4252): the agent
  can parse the user out and check the session id against the binding
  (`ssh-agent.c`, `parse_userauth_request`, `process_sign_request2`). When the server
  advertises `publickey-hostbound@openssh.com` (GitHub does), the client signs the
  host-bound form instead (OpenSSH PROTOCOL section 3.1, "Host-bound public key authentication"): the method is
  `publickey-hostbound-v00@openssh.com` and the server's host key follows the public
  key, so the signer sees the server too; the agent checks it against the binding.
  Verified the hard way: v0.1.0 accepted only the plain method and refused every push
  to GitHub while signing commits fine.
- An `ssh-keygen -Y sign` request signs a blob that starts with `SSHSIG` and carries the
  namespace (`ssh-agent.c`, `parse_sshsig_request`).
- OpenSSH's own agent implements per-key destination constraints over these
  (`restrict-destination-v00@openssh.com`, `identity_permitted`): refuses to sign on a
  forwarding hop, hides keys not permitted at the bound destination. taciturn implements
  the same decisions from a stored per-key policy instead of a constraint the client adds.

**F9. The connecting process can be identified without a race.** `getsockopt(SOL_LOCAL,
LOCAL_PEERCRED)` gives the peer's uid; `LOCAL_PEERTOKEN` (in `sys/un.h`, and in
`x/sys/unix` for darwin) gives its audit token, which `SecCodeCopyGuestWithAttributes`
turns into a `SecCode` to read the executable path and signing identifier
(`com.apple.ssh`, `com.apple.ssh-keygen` for Apple's tools *(verified)*) and to check a
`SecRequirement`. Secretive identifies the peer by pid, `sysctl` and `proc_pidpath`, walks
parents for display, and refuses nothing (`SigningRequestTracer.swift`).

**F10. GitHub's macOS runners are virtual machines without an enclave.** Guest VMs on Apple
Silicon have no Secure Enclave (Virtualization.framework; CryptoKit's `isAvailable` is
false there). Hardware tests run on a real Mac; CI runs everything else.

**F11. What the fleet already has.** primordium: `app` (lifecycle), `app/shutdown`,
`app/logger`, `filesystem/dirs` (`DataDir` → `~/Library/Application Support/<app>`),
`filesystem/pathcheck.ValidateSocket` (the 104-byte `sun_path` bound), `filesystem/umask`,
`filesystem/atomic`, `filesystem/flock`, `format` (console/json/markdown output), `fault`.
`golang.org/x/crypto/ssh` (already a primordium dependency): public-key and signature wire
formats for every host-key type including `sk-` and certificates, `ssh.Marshal`/
`Unmarshal`. `golang.org/x/sys/unix`: `LOCAL_PEERCRED`, `LOCAL_PEERPID`, `LOCAL_PEERTOKEN`,
`GetsockoptXucred`. cgo: the book allows a macOS release artifact that links Apple's SDK,
built with Xcode (`book/recipes.md`, "The host's C compiler"); `GO_CGO` declares it.
purego has one precedent (mycophonic/cordyceps, llama.cpp) and is rejected below.
forkcloser/openssh's `ssh-agent-install`/`ssh-agent-launchd` are the fleet's model for a
user LaunchAgent that runs a pinned package by its real path.

**F12. How the sessions reach an agent.** The sandbox denies `~/.ssh`, rewrites
`SSH_AUTH_SOCK` to a launchd socket it then denies, and allows only the unix sockets in
`sandbox.network.allowUnixSockets`; `limen-install-agent` pins the socket inside
`core.sshCommand` (`-o IdentityAgent=`) and the `ssh-keygen` wrapper, and already takes
`--socket PATH`. Replacing Secretive is, on the sessions' side, one path.

## The design

### Shape

One Go module, `github.com/forkcloser/taciturn`, one binary, `cmd/taciturn`, darwin/arm64
only, built with cgo against `Security.framework` and `CoreFoundation.framework` (system
frameworks; Xcode's clang, which the book treats as part of the machine). `GO_CGO=1` in the
root `.justfile`. Go `1.26.0` directive, the baseline.

```
cmd/taciturn/           the CLI and the agent entry point; flags parsed and paths
                        validated here (book/boundaries-go.md), nowhere deeper
internal/enclave/       the Secure Enclave: generate, load, public key, sign (cgo)
internal/keystore/      keys on disk: blob + metadata + policy, atomic, 0700/0600
internal/policy/        the decision: bytes and bindings in, allow/refuse out; pure Go
internal/protocol/      agent protocol framing and messages (RFC 9987, PROTOCOL.agent)
internal/agent/         the server: socket, connections, bindings, dispatch, audit
internal/peer/          who connected: uid, audit token, code identity, parent chain (cgo)
internal/launchd/       the LaunchAgent plist: install, uninstall, status
```

Library packages log nothing and return errors on a few sentinels per package
(`ErrRefused`, `ErrNoKey`, `ErrCorrupt`, `ErrUnavailable`, …; `book/errors-go.md`). The
command sets up `log/slog` once and owns every line printed.

### Why cgo, and what "pure Go" would mean here

There is no pure-Go road to the enclave: it is reached only through `securityd`/`ctkd`
over Apple's frameworks, with no public protocol underneath. Every option calls
`Security.framework`; the choice is how the calls are bound. Go's own `crypto/x509` links
the framework without cgo, but through `//go:cgo_import_dynamic` and assembly trampolines
reserved to the standard library (golang/go#32604); nothing outside it can do the same.

- **cgo** (recommended). The C compiler checks every call, argument type and constant
  against Apple's headers at build time; `kSecAttrTokenOID`'s absence from the public
  header is a compile error that makes one say why `toid` is used, not a nil at runtime.
  The whole surface is one file of about twenty functions. Costs: `CGO_ENABLED=1`, so the
  build needs Xcode's clang (the only target is darwin/arm64, the CI macOS runner has it,
  and the book names exactly this case: a macOS artifact linking Apple's SDK, built with
  Xcode, `book/recipes.md`), the lint lanes run once natively instead of per platform
  (`GO_CGO`), no cross-compilation (not wanted), and the race lane is cgo anyway.
- **purego** (`github.com/ebitengine/purego`, used once in the fleet, cordyceps for
  llama.cpp). `dlopen` + a Go declaration per C function; `CGO_ENABLED=0`. The ~20
  functions and ~25 `CFStringRef` constants are hand-declared from a reading of the
  headers: a wrong type or a wrong constant name is undefined behaviour or a nil at run
  time, with nothing checking it, in the one package where a wrong attribute silently makes
  a different key (F4). With cgo off, purego makes the Go runtime cgo-capable itself
  (`internal/fakecgo`, a Go re-implementation of `runtime/cgo`'s thread and TLS setup),
  and its README calls the library beta. That is more unverified code under a security
  boundary, bought with a C compiler we have anyway. Rejected for v1; nothing in the
  package layout prevents swapping the binding later, since `internal/enclave` is the only
  package that imports either.
- **Swift** would be a new language in the fleet with no lint baseline, no recipes, no
  primordium, and CryptoKit buys nothing the C API does not (F3). Rejected.
- **A Swift or C helper process** beside a pure-Go agent doubles the attack surface and the
  install story for nothing. Rejected.

### Keys

A key is created by the CLI, in the enclave, with:

- `kSecAttrKeyTypeECSECPrimeRandom`, 256 bits, `kSecAttrTokenIDSecureEnclave`,
  `kSecAttrIsPermanent = false`.
- A `SecAccessControl` with `kSecAccessControlPrivateKeyUsage` and the class the operator
  chose: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (`--use locked`, the bot's
  choice: signs while the screen is locked, until reboot) or
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (`--use unlocked`, Secretive's behaviour).
  No default: the flag is required, so the choice is written down in the command.

What is stored, under `~/Library/Application Support/taciturn/keys/` (primordium `dirs`
with app name `taciturn`; directory `0700`, files `0600`, written atomically):

- `<fingerprint>.blob`: the `kSecAttrTokenOID` bytes (F3), nothing else.
- `<fingerprint>.json`: name, created-at, class, the public key in OpenSSH wire form, the
  policy below. The fingerprint is `SHA256:` of the public key, the same string `ssh-keygen
  -l` prints.

The agent reads the directory on every request: a dozen small files at most, and it means
a CLI change (a new key, a policy edit, a deletion) is live at the next request with no
signal, no reload, no stale cache, and no second copy of the state (`principles.md`: "no
state kept twice").

Deleting a key deletes the two files. The enclave holds nothing of its own for a
non-permanent key, so that is the whole deletion; the public key stays registered on
GitHub until the human removes it, which `taciturn key delete` says.

### Policy, and the decision the agent makes

Per key, stored in its `.json`, set by the CLI:

```json
{
  "destinations": [
    {"user": "git", "host": "github.com", "hostkeys": ["ssh-ed25519 AAAA…", "ecdsa-sha2-nistp256 AAAA…", "ssh-rsa AAAA…"]}
  ],
  "sshsig": ["git"],
  "peers": ["anchor apple and (identifier \"com.apple.ssh\" or identifier \"com.apple.ssh-keygen\")"]
}
```

- `destinations`: where the key may authenticate. `host` is a label for the log and the
  listing; the **host keys** are the truth, since the protocol carries the server's key and
  its proof, never its name (F8). `taciturn key allow NAME --user git --host github.com
  --known-hosts FILE` copies the host's keys out of a known_hosts file; the sessions
  already have GitHub's pinned in `~/.claude/known_hosts` from GitHub's published list.
- `sshsig`: the namespaces the key may sign with `ssh-keygen -Y sign` (`git` for commits
  and tags). Empty means none.
- `peers`: who may ask. Each entry is either a code-signing requirement (Apple's
  requirement language, checked on the connection's audit token, F9) or
  `path=<glob>`, the peer's executable path as `SecCodeCopyPath` reports it. The default,
  set at `key create`, names **forkcloser/openssh's `ssh` and `ssh-keygen` only**, by path
  under every aqua root the machine runs tools from: the human's
  (`~/.local/share/aquaproj-aqua`) and the sessions' (`~/.local/share/limen-agent/aqua`,
  limen-install-agent's), so the environment that creates a key does not decide which
  client may use it (the fork's binaries carry an ad-hoc signature, so a path is what
  identifies them; the log records the cdhash of every peer, so the build that asked is
  on record). Until the fork is the sessions' client, the default also carries Apple's
  `anchor apple and identifier "com.apple.ssh"` / `"com.apple.ssh-keygen"` as a named
  interim allowance, removed in the release that follows the switch. `--peers any` turns
  the check off for a key; `key peers NAME --add/--remove` edits the list afterwards, and
  every entry is checked as the agent reads it (a glob the matcher takes, a requirement
  the framework parses), since the agent treats what it cannot read as unsatisfied and a
  stored typo would refuse every request. What the check is worth: it stops a client that speaks the
  agent protocol itself; a process that drives ssh is caught by the destination policy,
  not by this.

The agent's decision, per connection, in order; the first rule that applies ends it:

1. The peer's uid is not the agent's → close the connection. (Root is not stopped by
   anything on this machine and is out of scope.)
2. `session-bind` arrives → verify the host key's signature over the session id with that
   key (`x/crypto/ssh` verifies every type OpenSSH sends, `sk-` and certificates
   included); a bad signature, a second bind on a connection bound for authentication, or
   a duplicate session id with a different key → refuse and close. Record the binding.
   `is_forwarding = true` → record it; from here every identity is hidden and every
   signature refused: the key never travels through a forwarded agent.
3. `request identities` → the keys whose `destinations` include the bound host key; all
   keys with a non-empty policy when unbound (so `ssh-add -L` works from a shell); none on
   a forwarding binding. Hiding a key from `ssh` is what stops it offering the key at the
   wrong host, exactly as OpenSSH does.
4. `sign request`, connection bound for authentication → the data must parse as a userauth
   request (plain or host-bound) whose session id equals the bound one, whose host key,
   when it carries one, equals the bound host key, and whose public key is the requested
   key, the user must match a destination whose host keys include the bound host key, the
   peer must satisfy `peers`. Then sign.
5. `sign request`, connection unbound → the data must parse as an `SSHSIG` request with a
   namespace in `sshsig`; peer check; then sign. A userauth-shaped request on an unbound
   connection is refused: a client that does not bind is not Apple's `ssh` and has no
   business here.
6. `add`, `remove`, `remove all`, `lock`, `unlock`, any constrained variant, smartcard
   requests, any extension but `session-bind` and `query` → `SSH_AGENT_FAILURE`. The agent
   is read-only to its clients by construction; keys come from the CLI only.
7. Anything that does not parse, exceeds the size bound (64 KiB per message; `ssh-agent`'s
   own is 256 KiB) or arrives after the per-connection deadline → close.

Every request writes one audit record (below) whether allowed or refused, and a refusal
never says why to the client: `SSH_AGENT_FAILURE` is the whole answer, the reason is in
the log.

What this buys, concretely: a process that reaches the socket can make the bot
authenticate to github.com as `git` and sign a commit in the `git` namespace, and nothing
else: not another host, not a forwarded hop, not an arbitrary blob, not a web-origin
challenge. The rulesets then bound what a commit or a push can do (identity.md, "The veto
is the rulesets"). That is the whole threat the key was ever exposed to, now enforced
instead of assumed.

### Signing

`SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data)`:
the framework hashes, the enclave signs the digest, the result is DER `(r, s)`. The agent
decodes it (`encoding/asn1`) and returns the `ecdsa-sha2-nistp256` wire form, `mpint r ‖
mpint s`, through `x/crypto/ssh`'s `Signature`. The enclave package exposes the signature
as `(r, s)` and nothing DER leaves it. No `LAContext`: a `.privateKeyUsage`-only key needs
none (Secretive passes one only for presence-gated keys).

### The socket and the process

- A user LaunchAgent, `org.forkcloser.taciturn`, `RunAtLoad`, `KeepAlive`, running
  `taciturn agent` in the foreground, logs under `~/Library/Logs/org.forkcloser.taciturn/`.
  `taciturn install` writes the plist with the binary's **real** path (launchd starts it
  with `HOME` and the system `PATH`; an aqua proxy cannot resolve itself there — the
  openssh fork's lesson) and bootstraps it; `uninstall` boots it out. After an upgrade to
  a new package directory, `taciturn install` again; `limen-install`'s nightly job does
  the same for the ssh agent today and can do it for taciturn.
- The socket: `~/Library/Application Support/taciturn/agent.sock` (78 bytes, under the
  104-byte bound, checked with `pathcheck.ValidateSocket` at the one place the path is
  assembled). Directory `0700`, socket `0600`, a stale socket file unlinked at start, a
  lock file (`filesystem/flock`) so a second agent refuses to start. Outside `~/.ssh`, which
  the sessions cannot read, and on a stable path, which the sandbox allow-list needs.
- Not launchd socket activation: it would add `liblaunch` and a second code path for the
  listener, for no property the sandbox or the sessions need; `KeepAlive` restarts the
  agent, and a restart is a few milliseconds without a socket.
- One goroutine per connection, a deadline per connection (10 s idle), a bound on
  concurrent connections, a bound per message. No state shared across connections but
  the store on disk.
- `SSH_AUTH_SOCK` is not exported anywhere by taciturn: the human's shells keep the
  YubiKey agent; the sessions get taciturn through `limen-install-agent --socket`.

### The audit log

One line per request, `log/slog` JSON, to `~/Library/Logs/org.forkcloser.taciturn/audit.log`
(the agent's only output): time, connection id, peer pid, path, signing identifier and
whether the signature was valid, the parent chain as far as `sysctl` gives it (best
effort, for the reader; nothing decides on it), the request type, the key fingerprint, the
bound host key fingerprint and the user for an authentication, the namespace for an
sshsig, and `allow` or `refuse` with the rule that decided. `taciturn log` prints it,
`--follow` tails it, `--json` passes it through. The enclave is not asked about anything a
rule refused, so the log is also the record of what was *not* signed.

### The CLI

```
taciturn agent                                  foreground; what the LaunchAgent runs
taciturn install | uninstall | status           the LaunchAgent and the socket
taciturn doctor                                 enclave available, agent loaded, socket mode,
                                                store permissions, each key loads and its
                                                public key matches, in one report
taciturn key create NAME --use locked|unlocked [--peers any]
taciturn key list [--format console|json|ssh]   ssh: authorized_keys lines, for GitHub
taciturn key show NAME                          public key, fingerprint, class, policy, last uses
taciturn key allow NAME --user U --host H --known-hosts FILE
taciturn key disallow NAME --host H
taciturn key peers NAME [--add ENTRY] [--remove ENTRY]   who may ask; an entry is checked as the agent reads it
taciturn key sshsig NAME --namespace git [--remove]
taciturn key delete NAME --yes                  prints the reminder to revoke on GitHub
taciturn key rotate NAME                        successor created and served; old key renamed NAME@<date>
taciturn key retire NAME@<date>                 no longer served; files kept until delete
taciturn key signers NAME                       the allowed-signers line(s), with the validity window
taciturn log [--follow] [--json] [--key NAME]
```

Output goes through primordium `format` (console by default, `--format json` everywhere).
`key create` prints the public key once, in the form GitHub takes. Every command but
`agent` is a plain process over the store; none talks to the agent, and none needs it
running except `install`/`status`/`doctor`.

### Threat model

| Adversary | Can | Cannot | Why |
|---|---|---|---|
| Code in a session (sandboxed, same uid) | connect to the socket; get signatures within a key's policy: authenticate to github.com as `git`, sign in the `git` namespace | reach the enclave (F6); read the blobs (sandbox read-deny, below); use the key elsewhere; forward it | the policy and the sandbox |
| A process of the user outside any sandbox | everything above; read the blob files; load the blob through the enclave and sign anything, bypassing the policy | extract the key; use the blob on another Mac | the enclave; the residual is named below |
| Root on this Mac | everything the user can | extract the key | the enclave |
| Disk image, backup, another Mac | nothing: the blob only unwraps in this enclave | | F3 |
| A server the bot connects to | learn the public key; be authenticated to only if its host key is in the policy | replay: every signature covers a fresh session id | the protocol |
| A forwarded agent on a remote host | nothing: refused at the binding | | rule 2 |

**The residual: a blob on disk is usable by an unsandboxed process of the user.** It
cannot extract the key, it cannot use it elsewhere, it *can* sign without the policy. The
mitigations are the directory mode, the sessions' sandbox read-deny on
`~/Library/Application Support/taciturn/keys` (a `limen-install-agent` change, like its
`~/.ssh` deny; without it a session can read the blob but still not use it, F6), and the
log. The alternative is the keychain, whose item ACL binds the blob to the creating
program's code signature; it needs the entitlement, the profile, the `.app` wrapper, and a
distribution signing identity we do not have (F3), and even then an upgrade changes an
ad-hoc program's identity and loses the item. Secretive's socket is just as open as ours
and enforces nothing once reached; against the adversary that matters (code in a session)
taciturn is strictly stronger. This is decision 1 below.

**Not addressed, by design:** a compromise of the user account outside the sandbox, root,
and a compromise of the sandbox itself. The key's damage is bounded by the rulesets and
revoked in a click, which the book already relies on.

### Distribution and install

- Released like the fleet (`book/releasing.md`): a signed tag, the CI lane, goreleaser
  with keyless cosign and a GitHub artifact attestation, one asset
  `taciturn_<version>_darwin_arm64.tar.gz`, built on the macOS runner with Xcode's clang
  (cgo; the release shape and the `build` recipe kept twins).
- Pinned on machines through aqua as a `github_release` package with
  `github_artifact_attestations` and the checksum, in `limen-install`'s global config next
  to forkcloser/openssh; Renovate moves the pin; the nightly job ships it and re-runs
  `taciturn install`. The LaunchAgent runs the package's real path.
- Go's linker ad-hoc signs darwin/arm64 binaries; the enclave works with that (F3), and
  nothing here depends on the signature being stable across builds, which is what makes
  the keychain-less design survive upgrades.
- No Homebrew formula in v1: aqua is the fleet's path. A formula in `homebrew-brews` is a
  follow-up if a machine outside the rig wants it.

### Testing

The book's shape (`testing-go.md`): one contract per package in `contract_test.go`, a
bounded walk, a fuzz target, black-box.

- `protocol`: every message type at its edges (empty, maximal, one past the bound,
  truncated at every field boundary), round trips, and OpenSSH's own test vectors where
  `PROTOCOL.agent` gives them. Fuzz on the decoder.
- `policy`: the whole decision table above as a bounded walk over (binding state ×
  request kind × data shape × policy) with every edge: unbound/auth-bound/forward-bound,
  userauth with the right/wrong session id, user, key, host key; sshsig with each
  namespace; each refused request type. The package is pure functions, so the walk is
  exhaustive and fast.
- `keystore`: atomic writes, modes, a corrupt file, a missing pair, concurrent reader
  while the CLI writes; the drop-in checks beside primordium's own.
- `enclave`: a **hardware lane**, `just test enclave`, that skips with a named reason
  when `SecKeyCreateRandomKey` reports no token and runs on a real Mac before every
  release: generate, blob round trip through a **separate process**, public key equality
  before the first signature (the F4 trap as a permanent regression test), sign and verify
  with Go's `crypto/ecdsa`, the class readable from the reloaded key, and a deliberately
  wrong load (no `toid`) shown to produce a different key, so the trap stays documented by
  a test that fails if Apple ever changes it.
- `agent`, end to end, hardware lane: the agent on a temporary socket, Apple's `ssh -o
  IdentityAgent=` against a local `sshd` (the fork's `sshd` with a test config that accepts
  `ecdsa-sha2-nistp256`), a destination that is allowed and one that is not, a forwarded
  agent over that connection refused, `ssh-keygen -Y sign` and `-Y verify` in an allowed
  and a refused namespace, `ssh-add -L` listing, and `ssh-add` refused. *(Done 2026-10-12,
  on this machine, with the real clients: a key made by `taciturn key create`, listed by
  Apple's `ssh-add -L`, signed for by `ssh-keygen -Y sign -n git` and verified by
  `ssh-keygen -Y verify`, the `file` namespace refused, `ssh-add` of a key refused, and a
  real `ssh -T git@github.com` whose session binding verified against GitHub's ed25519
  host key before GitHub refused the unregistered key; the audit log recorded each. The
  local-`sshd` leg is still to run once the fork accepts P-256.)*
- The locked-screen claim (F7): a manual procedure in the README, run once at
  implementation and at every macOS major: start a signature in 30 s, lock the screen,
  read the result.
- CI: every lane but the hardware ones, on the usual matrix; the hardware lanes skip there
  and say so.

### Key rotation (P1, in scope)

A key changes hands for three reasons: the move from Secretive (once), a suspected
compromise (rare, urgent), and routine rotation (which should be cheap enough to happen).
Today every one of them is a flag day: a new key means a hand-edited `.lint-signers` in
every repository, a GitHub registration, a re-run of the session installer, and nothing
says when the old key stops being acceptable. The same is true of the human's YubiKey.
Rotation is therefore designed for **any signer**, bot or human, with taciturn owning the
local half and limen the fleet half. Apostasie asked for this as P1 (2026-10-12).

**The mechanism is the allowed-signers format, not a file swap.** `.lint-signers` is an
OpenSSH allowed-signers file, and the format carries `valid-after="YYYYMMDD[HHMMSS]"` and
`valid-before=` per line (`ssh-keygen(1)`, ALLOWED SIGNERS). A rotation is two edits that
commute: the successor key is **added** with `valid-after` at its creation time, and the
retired key gets `valid-before` at its retirement time. Commits the old key signed before
that instant keep verifying forever (`git log --show-signature` reads the time of the
signature against the window); a commit it signs after is refused by `just lint`'s commit
check and by every reviewer running it. No line is ever deleted, so history stays
verifiable offline, and a compromised old key is dead at a date, not at whenever the last
repository got its PR. The `namespaces="git"` field stays as it is.

**The steps, and who runs them:**

1. `taciturn key rotate NAME` — creates NAME's successor in the enclave with the same
   class and policy, names it `NAME` and the old one `NAME@<date>`, serves **both** until
   the old one is retired (a session mid-push keeps working), prints the successor's
   public key in GitHub's form and in allowed-signers form with `valid-after`, and writes
   the public-key file `limen-install-agent` takes. For a human's YubiKey the equivalent is
   `ssh-keygen`; the next steps are the same.
2. **GitHub registration** — the successor goes on the account as an authentication key
   and a signing key. For the bot this is a login as the bot (two-factor), which no
   session can do and no session should: manual, with the two URLs printed. Automating it
   needs a fine-grained token of the bot with `admin:public_key` and
   `write:ssh_signing_key`, a secret at rest, which is the thing this whole design avoids;
   decision 9 asks whether that trade is wanted. The old key is removed from GitHub at
   step 5; GitHub keeps the badge on commits verified before the removal.
3. **The fleet** — every onboarded repository carries the same signers, so
   `.lint-signers` is a content-pinned canonical file of limen's, and the fleet already has
   a rollout for those: a limen release, Renovate's bump in every repository, the checksum
   workflow's converge. `limen signers add <pubkey> [--valid-after T]` and
   `limen signers retire <fingerprint> --valid-before T` edit limen's canonical file
   deterministically (sorted, idempotent, the format validated); an **add rides the next
   limen release**, and step 4 waits for it to converge, which a routine rotation can
   afford. The one case that cannot wait a release cycle is the compromised key:
   `limen github signers rollout` is scoped to **retire only**, one signed commit and one
   pull request per onboarded repository with a fixed title, and the release carries the
   same edit behind it. Review stays the normal flow. Agreed with Limen 2026-10-12; limen's
   to build.
4. **The sessions** — `limen-install-agent … <new public-key-file>` re-pins
   `user.signingkey` to the successor; sessions restart to pick it up; `taciturn log`
   shows the last use of the old key.
5. `taciturn key retire NAME@<date>` — once no session has used the old key for the grace
   period (the log says), the agent stops serving it; `limen github signers rollout` has
   already set its `valid-before`; the key is removed from GitHub by hand; the two files
   are deleted locally (`taciturn key delete`).

Compromise is the same sequence with `valid-before` set to the moment of discovery, step 5
first, and the GitHub removal immediately: the sessions stop at once (the agent no longer
serves the key), and every commit it signs after that instant is refused everywhere.

What `taciturn` carries for this: the successor relationship in a key's metadata
(`predecessor`, `successor`, `created`, `retired`), `key list` showing the chain, the
allowed-signers output with the window, and the rule that a retired key is never served
and never deleted by `rotate`. What it does not carry: any GitHub credential.

### Migration from Secretive

The first rotation, from Secretive's key to taciturn's, by the steps above, with two
additions: `limen-install-agent --socket ~/Library/Application\ Support/taciturn/agent.sock …`
re-pins the sessions' socket at step 4 (the sandbox read-deny for the key store is a
`limen-install` change, Limen's), and Secretive is uninstalled at step 5, with its socket
entry removed from the sandbox allow-list. Secretive's key cannot move: it is a new key,
registered, rolled out and retired like any other.

### Dependencies

`go.mod`: `github.com/mycophonic/primordium`, `golang.org/x/crypto`, `golang.org/x/sys`,
and the fleet's test helper. cgo: `Security.framework`, `CoreFoundation.framework`. That
is all. The lint baseline's depguard admits the standard library and the module; the
overlay allows these three.

### Out of scope for v1, noted

Presence-gated keys (`.userPresence`); ML-DSA keys; a `restrict-destination` constraint
accepted from `ssh-add` (the policy is the operator's, not the client's); notifications
(no app bundle, no `UserNotifications`; the log is the notification); Linux.

## Decisions (Apostasie, 2026-10-12)

Each was put as a question with the alternatives; the answer and its reason stand here.

1. **Key blobs on disk**, `~/Library/Application Support/taciturn/keys`, `0700`/`0600`,
   with the sessions' sandbox read-deny. The keychain needs an `.app`, a provisioning
   profile and a distribution identity (F3), and loses the item on every ad-hoc rebuild.
2. **The bot key's class is `AfterFirstUnlockThisDeviceOnly`**: it signs while the screen
   is locked, until reboot, so unattended sessions finish their pushes. Same exposure as
   while present, within the policy.
3. **Peer requirement on by default, naming our ssh fork only** (path under aqua's
   package directory, the human's root and the sessions'), with Apple's `ssh`/`ssh-keygen`
   as a named interim allowance until the fork is the sessions' client (it ships P-256
   since v10.6.1.2). The bot then has exactly one client. `--peers any` per key.
4. **A user-authentication signature on an unbound connection is refused.** Only sshsig
   requests are answered unbound. Breaks no OpenSSH since 8.9; refuses every other client.
5. **Own protocol loop**, not `x/crypto/ssh/agent.ServeAgent`: a 64 KiB bound, a
   deny-by-default dispatch, per-connection binding state. `x/crypto/ssh` for keys,
   signatures and host-key verification.
6. **Names as proposed**: `taciturn`, `org.forkcloser.taciturn`,
   `~/Library/Application Support/taciturn/{keys,agent.sock}`,
   `~/Library/Logs/org.forkcloser.taciturn/`.
7. **forkcloser/openssh gains ECDSA P-256** (a LibreSSL build, the config left
   ed25519-only, the sessions naming `ecdsa-sha2-nistp256` alone) and becomes the bot's only
   ssh; `limen-install-agent` points the sessions at the fork's `ssh` and `ssh-keygen` by
   real path. Requests to the Forkcloser Maintainer and to Limen. Apple's ssh is the
   interim.
8. **The repository is public, MIT; the first PR is `limen bootstrap` plus this
   document**, through The Reviewer; then one PR per package in dependency order
   (`protocol`, `policy`, `keystore`, `enclave`, `agent`, `peer`, `launchd`, `cmd`), the
   hardware lane run locally before each. Apostasie creates `forkcloser/taciturn` and
   grants `closer-claudio`.
9. **The bot's GitHub key registration stays manual**: taciturn prints the key in
   GitHub's form and the two URLs; no token of the bot at rest anywhere.
10. **Rotation tooling: taciturn local, limen fleet.** `taciturn key rotate|retire|signers`
    here; `limen signers add|retire` editing limen's canonical `.lint-signers` (an add
    rides the limen release) and `limen github signers rollout` for the urgent retire
    only, on the allowed-signers `valid-after`/`valid-before` window, never a deletion.
    Requested from and shaped with Limen the same day.
11. **cgo, not purego, not wazero.** The C compiler checks the Security.framework calls;
    purego would hand-declare them unchecked under a security boundary; wazero has no
    library to run, since the work happens in the enclave behind Mach IPC, and would still
    need the same binding as host functions.

## v0.2: keys in the data-protection keychain, in a signed bundle

Status: **decided by Apostasie, 2026-10-13**, after the experiment below ran on this
machine. v0.1 is in service (the bot signs and pushes through it); v0.2 changes where the
key lives and what ships, not the protocol, the policy or the socket.

### Why

Decision 1 put the wrapped key blob in a `0600` file. That file is the key: the enclave
unwraps it for any process on this Mac that presents it, so the fence around the bot key
is the filesystem (the directory's mode, the sessions' sandbox read-deny) and the agent's
policy, which only governs processes that ask the agent. A same-user process that reads
the file needs no agent. With a paid Apple developer account on hand, the question was
whether code signing buys a better story. It does, in one specific way: a key created in
the **data-protection keychain under a keychain access group** is reachable only by code
signed by the team with that group, so the blob stops being a file anyone can read, and
the only road to the key for everything else on the machine is the agent's socket and its
policy.

### Facts, verified 2026-10-13

The probe is `_scratch/keychain-experiment` (a cgo program and `run.sh`), built into
`Probe.app` with an `Info.plist`, an entitlements file naming
`com.apple.application-identifier`, `com.apple.developer.team-identifier` and
`keychain-access-groups = [<team>.org.forkcloser.taciturn]`, a development provisioning
profile for the App ID `org.forkcloser.taciturn` made in the developer portal (no
capability enabled: the profile carries `keychain-access-groups` for the team prefix on
its own), and signed with the Apple Development identity.

- **F13 *(verified)*** The bundled binary, launched by path from a shell, creates a
  permanent P-256 enclave key in the data-protection keychain (`kSecAttrIsPermanent`,
  `kSecUseDataProtectionKeychain`, `kSecAttrAccessGroup`), with the same
  `SecAccessControl` as v0.1 (private-key usage, `AfterFirstUnlockThisDeviceOnly`), lists
  it with its group, and signs with it. No `-34018`. The bundle moved to another directory
  and the binary reached through a symlink (the aqua proxy's way) both keep working.
- **F14 *(verified)*** The same binary copied out of the bundle and re-signed ad hoc, and an
  unrelated ad-hoc binary, both get `-25300` (item not found): outside the group the key
  is invisible, not merely refused.
- **F15 *(verified)*** The signed binary copied out of its bundle, without the profile
  beside it, is killed at launch by the kernel: restricted entitlements require the
  profile. A bare binary with these entitlements cannot exist; the bundle is the unit.
- **F16 *(verified)*** The keychain does not change what the key is. The `toid` blob of a
  keychain-resident key, obtained by the entitled process, loads with
  `SecKeyCreateWithData` in a bare process and signs. The group protects the item, not
  the material: v0.2's agent therefore never exports a blob, and `enclave.Key.Blob()`
  goes.
- **F17 *(verified)*** A v0.1 keychain-less key, rebuilt from its blob, is stored in the
  data-protection keychain under the group with one `SecItemAdd` of the key reference,
  then listed and used from the bundle: **migration without rotation**, the bot's key and
  its GitHub registration unchanged.
- **F18 *(verified)*** A keychain-resident key of the locked class signs with the screen
  locked, from the bundle; the same minute, taciturn's v0.1 key authenticated to GitHub
  with the screen locked.
- **F19 *(assumed, proven by the first release)*** A Developer ID Application signature
  with a Developer ID provisioning profile behaves as the development pair did for
  `keychain-access-groups`; Apple documents both as the two ways to carry that
  entitlement on macOS. The first v0.2 release run is the proof, read before the pin.

### What changes

- **Keys** (`internal/enclave`, `internal/keystore`): a key is created permanent in the
  data-protection keychain under the access group, `kSecAttrLabel` and
  `kSecAttrApplicationTag` set to its fingerprint; loaded by `SecItemCopyMatching` on the
  label, the public key checked against the record as before (the F4 guard, now against
  substitution in the keychain); deleted by `SecItemDelete`. The keychain tells keys
  apart by their own attributes, not by the label: it stores two different keys under one
  label as two items (seen on the hardware, 2026-10-13), so the uniqueness of the label is
  taciturn's to enforce, by a lookup before every store. The store keeps the record
  file only (name, class, public key, policy, lineage); no blob file is written, and
  `Blob()` is gone from the enclave API. The access group is read at run time from the
  process's own `keychain-access-groups` entitlement (`SecTaskCopyValueForEntitlement`):
  the entry that ends in `org.forkcloser.taciturn`, whatever else the plist lists and in
  whatever order; a process without one gets `ErrUnavailable` with the reason "not
  running from the signed bundle", which `doctor` prints. No team identifier in the
  source. The item survives upgrades: the fence is the team and the group, not the
  binary's cdhash, which is exactly the v1 objection to the keychain (an upgrade changes
  an ad-hoc program's identity and loses the item) that the Developer ID signature
  removes.
- **The bundle**: the release ships `Taciturn.app/Contents/{Info.plist,
  embedded.provisionprofile, MacOS/taciturn}`; `CFBundleIdentifier` is
  `org.forkcloser.taciturn`, the LaunchAgent label unchanged. It is a command-line tool
  that happens to live in a bundle: launched by path, never through Launch Services. aqua's
  registry entry points its `files` at `Taciturn.app/Contents/MacOS/taciturn`; `taciturn
  install` writes the LaunchAgent with that path, resolved as today.
- **Release lane**: goreleaser builds the binary as now; a post-build hook assembles the
  bundle and runs `codesign --sign "Developer ID Application" --options runtime
  --timestamp --entitlements`; the archive carries the bundle. The identity comes from
  repository secrets: `APPLE_DEVELOPER_ID_P12` (base64 of the `.p12`),
  `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_PROVISIONING_PROFILE` (base64 of the
  Developer ID `.provisionprofile`). The workflow imports the certificate into a temporary
  keychain it creates and deletes in the same job, grants `codesign` the partition, and
  never writes the key to disk unencrypted outside that keychain. No notarization in
  v0.2: aqua downloads without a quarantine attribute and the tool runs by path, so
  Gatekeeper is not in the path; revisited if it ever is.
- **Migration**: `taciturn key import` walks the store, moves each v0.1 blob into the
  keychain under the key's fingerprint (F17), checks the public key, signs a test message
  with the keychain-resident key and verifies it, and only then deletes the blob file: a
  key that lists but will not sign is caught while the blob still exists. `doctor`
  reports a store that still has blobs. Order on a machine: pin v0.2,
  install (the LaunchAgent now runs the bundle), `key import`, verify a signature in the
  audit log, done; the sessions see the same key throughout.
- **Peers by requirement** (follow-up, with forkcloser/openssh): once the fork's `ssh` and
  `ssh-keygen` carry a Developer ID signature, the default peer entries become
  requirements, `anchor apple generic and certificate leaf[subject.OU] = "<team>" and
  identifier "org.forkcloser.ssh"` and the same for `ssh-keygen`, in place of the path
  globs under the aqua roots; the identifiers are the ones the fork's `build.sh` sets today.
- **Testing**: the enclave and agent hardware tests need the entitlement, so a
  `test-hardware` recipe builds each hardware test binary, wraps it in a development
  bundle signed with the Apple Development identity and the development profile at
  `~/Library/MobileDevice/Provisioning Profiles/taciturn-dev.provisionprofile` (or
  `TACITURN_DEV_PROFILE`), and runs it; the tests skip where the entitlement is absent, so
  CI and the sandbox stay green and read nothing they cannot.
- **Threat model**, amended: "same-user process reads the blob" moves from *can sign* to
  *cannot see the key*; what remains able to sign without the agent is code signed by the
  team with the group, root, and a securityd compromise. The audit log and the policy are
  unchanged.

### Decisions (Apostasie, 2026-10-13)

12. **Keys in the data-protection keychain under `<team>.org.forkcloser.taciturn`**,
    permanent, labelled by fingerprint; the record file stays, the blob file goes, the
    agent exports no key material (F16).
13. **taciturn ships as `Taciturn.app`**, signed with the team's Developer ID and an
    embedded Developer ID provisioning profile, launched by path; aqua and the
    LaunchAgent point inside the bundle (F13, F15).
14. **The release lane signs in CI** from the three repository secrets above, in a
    temporary keychain; no notarization in v0.2.
15. **Existing keys are imported, not rotated** (F17): `taciturn key import`, once per
    machine; GitHub and every `.lint-signers` stay as they are.
16. **The access group is read from the entitlement at run time**, the entry ending in
    `org.forkcloser.taciturn`; a build without it cannot touch keys and says so.
17. **The fork's binaries get a Developer ID signature** so peers are named by
    requirement; until then the path entries stand (Forkcloser Maintainer's side).

## Appendix: the experiments

Scratch programs under `$TMPDIR/se-c` and `$TMPDIR/se-swift` (not kept), compiled with
Xcode 27's clang and swiftc, ad-hoc signed by the linker (`codesign -dv` says
`Signature=adhoc`, no team), run in a Terminal outside the Claude sandbox unless stated.

1. `se.c` — `SecKeyCreateRandomKey` with the enclave token, non-permanent, access control
   `AfterFirstUnlockThisDeviceOnly | privateKeyUsage`.
   - Inside the sandbox: `OSStatus error -26276 - Failed to generate keypair` (also without
     the access control). A software EC key in the same program: `created: blob 97 bytes`.
   - Outside: the key is created; `SecKeyCopyExternalRepresentation` on it:
     `error -4 - export not implemented for key <SecKeyRef:('com.apple.setoken')>`.
2. `se2.c` — same creation, then `SecKeyCopyAttributes`: `tkid = "com.apple.setoken"`,
   `toid = <324 bytes>`, `accc = "<SecAccessControlRef: cku;…>"`; `toid` written to
   `key2.blob`, the public key (X9.63, 65 bytes) to `key2.pub`.
3. `se.swift` — CryptoKit `SecureEnclave.P256.Signing.PrivateKey(accessControl:)`:
   `created: blob 324 bytes, pub 64 bytes`; a new process:
   `loaded from blob; pub matches: true sig 64 bytes, verifies: true`.
   `se load key2.blob key2.pub` (the C blob into CryptoKit):
   `pub matches true verifies: true`.
4. `se3.c` — `SecKeyCreateWithData(blob, {type EC, class private, tkid SE})`: a key is
   returned, its attributes show a **different** `toid` (284 bytes) and `klbl`; its own
   signatures verify with its own public key and not with the stored one:
   `verifies with loaded key's own pub: 1; with file pub: 0`. Same for the CryptoKit blob.
5. `se4.c` — five attribute variants:
   ```
   A: data=blob, attrs+toid=blob:        pub matches 1, signed 1, verifies with original pub 1
   B: data=empty, attrs+toid=blob:       pub matches 1, signed 1, verifies with original pub 1
   C: data=blob, attrs+perm=false:       pub matches 0, signed 1, verifies with original pub 0
   D: data=empty, attrs={tkid,toid}:     pub matches 1, signed 1, verifies with original pub 1
   E: data=blob, attrs={tkid} only:      pub matches 0, signed 1, verifies with original pub 0
   ```
   The data argument is ignored; the `kSecAttrTokenOID` attribute is the key. Apple's
   `SecKey.m` (`SecKeyCreateWithData`: `if (tokenID != NULL) key = SecKeyCreateCTKKey(…)`,
   `keyData` unused) and `SecCTKKey.m` (`objectID != nil` → `objectForObjectID:`, else
   `// Generate new key`) say the same.
6. `se5.c` — the key loaded by variant D, from both blobs:
   `<SecAccessControlRef: cku;ock(true);odel(true);osgn(true);oa(true);okd(true)>`.

Other checks: `codesign -dv /usr/bin/ssh` → `Identifier=com.apple.ssh`; `ssh-keygen` →
`com.apple.ssh-keygen`; `/usr/bin/ssh -V` → `OpenSSH_10.3p1, LibreSSL 3.3.6`;
`security find-identity -v -p codesigning` → one "Apple Development" identity;
`sys/un.h` → `LOCAL_PEERTOKEN 0x006`; `x/sys/unix` darwin → `LOCAL_PEERPID`,
`LOCAL_PEERTOKEN`, `GetsockoptXucred`; the Secretive socket exists at
`~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh` and is the one
entry in the sessions' `allowUnixSockets`; the forkcloser agent socket under `~/.ssh` is
unreadable from a session.
