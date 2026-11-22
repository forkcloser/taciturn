# taciturn: design

An ssh-agent for keys in the Mac's Secure Enclave, for processes that work unattended.
This document says what taciturn is and why, as of v0.4.0: the facts it rests on, the
design, the threat model, and the decisions with their dates. Fact and decision numbers are
stable; the code refers to them. A number that is missing was a fact or a decision about
something that no longer exists.

## Why

The bot's key (`closer-claudio`) authenticates the Claude sessions' pushes and signs their
commits. It has to be bound to hardware and not exportable, usable without a touch, and
usable while the screen is locked, since the sessions work when nobody is there. It was
first served by [Secretive](https://github.com/maxgoedjen/secretive), which fell short in
four ways:

- It is a GUI application built by someone else, which cannot be pinned, attested or
  reviewed the way the rest of the machine is.
- Its keys stop signing when the screen locks
  ([maxgoedjen/secretive#462](https://github.com/maxgoedjen/secretive/issues/462)).
- It enforces nothing about what a key is used for: any process that reaches the socket
  gets a signature for any host, any user, any namespace, through any forwarding.
- It cannot be inspected from a shell.

taciturn is the replacement: one Go binary, darwin/arm64 only, that is the agent and the
command line, keeps its keys in the Secure Enclave, runs as a user LaunchAgent, and signs
only what a per-key policy allows. Its consumers are the sessions, through their sandbox;
its operator is a human, from a shell.

### Goals

1. Private keys that never exist outside the Secure Enclave, usable without a touch, usable
   while the screen is locked when the key says so.
2. A signature only for what the key is allowed to do: a named destination (host key and
   user), a named SSHSIG namespace, never through forwarding, never for an unknown shape of
   data.
3. Every use recorded: which process, which key, which destination, allowed or refused.
4. A command line to create, list, inspect, constrain, rotate, retire and delete keys, and
   to install the agent.
5. The fleet's standards: limen-onboarded, the book's testing shape, pinned and attested
   releases, minimal dependencies.

### Non-goals

- Touch ID, Apple Watch or passcode gates. A reflexive tap is theater for a bot; the
  human's YubiKey keeps its touch. Keys are made with private-key usage and nothing else.
- Replacing the human's agent or `SSH_AUTH_SOCK` for humans. taciturn exports nothing into
  anyone's environment; a client is pointed at its socket by `IdentityAgent`.
- Smart cards, PKCS#11, FIDO, software keys, key export. The enclave has no export.
- Linux, Windows, Intel Macs.
- ML-DSA keys: the Security.framework C API does not expose the enclave's, and GitHub does
  not accept them.
- Notifications. The audit log is the notification; a first notification is the first
  step toward a macOS application.

## Facts the design rests on

**F1. The Secure Enclave signs ECDSA P-256 and nothing else usable here.** No ed25519, no
RSA. Every taciturn key is `ecdsa-sha2-nistp256`.

**F2. The sessions' ssh is forkcloser/openssh.** It is built with P-256 since v10.6.1.2
and signed with the team's Developer ID since v10.6.1.6; its shipped configuration accepts
no ECDSA form, so a client that uses a taciturn key names
`PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256` itself.

**F3. An enclave key has a wrapped form, and the wrapped form is the key to this
enclave.** A key made with `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` carries the
attribute `kSecAttrTokenOID` (wire name `toid`, a few hundred bytes): the key, wrapped by
this machine's enclave. It is useless on another Mac, and on this one any process that
holds it can have the enclave sign with it (F16). v0.1 kept that blob in a file; it is
read today by `key import` alone.

**F4. Rebuilding a key from its blob has a trap that makes a new key silently.**
`SecKeyCreateWithData(data, attributes)` with the token id in the attributes ignores `data`
and reads `kSecAttrTokenOID` from the attributes; when it is absent the call succeeds and
returns a different, fresh key. The blob therefore goes in the attributes, and a rebuilt
key is compared with the stored public key before anything is signed with it
(`enclave.Import`). A key looked up in the keychain is compared the same way
(`enclave.Load`), against substitution.

**F5. The access class is the key's own.** It is set when the key is made and nothing
changes it later.

**F6. The enclave is unreachable from inside the sessions' sandbox.**
`SecKeyCreateRandomKey` fails there with `-26276`. The agent is an unsandboxed process of
the user, and a session only ever reaches its socket.

**F7. Locked-screen behaviour follows the class.** A key made
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` signs from the first unlock after boot
until the next boot, screen locked or not; one made
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` signs only while the session is unlocked,
and cannot even be created while it is locked (`errSecInteractionNotAllowed`, `-25308`).

**F8. The agent protocol carries the destination, and OpenSSH sends it.**
[RFC 9987](https://datatracker.ietf.org/doc/html/rfc9987) and OpenSSH's `PROTOCOL.agent`:

- Before it lists identities, `ssh` (8.9 and later) sends the `session-bind@openssh.com`
  extension: the server's host key, the session identifier, the host key's signature over
  it from the key exchange, and whether the connection is being forwarded. The signature
  makes the binding a proof of which server the connection is for.
- A public-key authentication request signs the session identifier followed by the
  `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 section 7), which names the user. When the server
  advertises it, GitHub among them, the client signs the host-bound form instead
  (`publickey-hostbound-v00@openssh.com`), which carries the server's host key after the
  public key.
- An `ssh-keygen -Y sign` request signs a blob that starts with `SSHSIG` and carries the
  namespace (`PROTOCOL.sshsig`).

**F9. The connecting process is identified without a race.** `LOCAL_PEERCRED` gives the
peer's uid, and `LOCAL_PEERTOKEN` its audit token, which `SecCodeCopyGuestWithAttributes`
turns into the code that connected: its path, its signing identifier, and a code
requirement evaluated against it. An audit token names one process image; a pid can be
reused and is read for the log only.

**F10. GitHub's macOS runners have no enclave.** They are virtual machines. The tests that
need the enclave run on a real Mac; CI runs everything else.

**F12. How the sessions reach an agent.** Their sandbox allows the unix sockets it lists
and denies reading the key store. `limen-install-agent` points `ssh` at the socket
(`IdentityAgent` in an included `ssh_config`, and `core.sshCommand`) and `ssh-keygen`
through a wrapper that sets `SSH_AUTH_SOCK` to it.

**F13. A bundled binary can keep enclave keys in the data-protection keychain.** A binary
inside an `.app` bundle that carries a provisioning profile granting
`keychain-access-groups`, launched by path, creates a permanent enclave key under the
access group, finds it again and signs with it.

**F14. Outside the access group the key is invisible.** The same binary re-signed ad hoc,
or any other program, gets `errSecItemNotFound` (`-25300`).

**F15. The bundle is the unit.** A binary signed with these entitlements and run without
the profile beside it is killed at launch.

**F16. The keychain protects the item, not the material.** The blob of a keychain key,
read by an entitled process, loads and signs in any process. So no blob ever leaves the
enclave package.

**F17. A key rebuilt from a v0.1 blob is stored in the keychain with one `SecItemAdd`.**
The key, its public half and its GitHub registration stay what they were.

**F18. A keychain key of the locked class signs with the screen locked,** from the bundle.

**F19. A Developer ID signature with a Developer ID provisioning profile carries the
access group** as the development pair of F13 does. The released bundle has kept and used
the bot's key since v0.2.0 (2026-10-14).

## The design

### Shape

One Go module, `github.com/forkcloser/taciturn`, one binary, `cmd/taciturn`, built with cgo
against `Security.framework` and `CoreFoundation.framework`.

```
cmd/taciturn/        the exit code; everything else is internal/cli
internal/cli/        the command line: parsing, dispatch, reporting
internal/enclave/    the Secure Enclave and the keychain: make, store, load, sign (cgo)
internal/keystore/   the records on disk: what each key is and may do
internal/policy/     the decision: facts in, allow or refuse out
internal/protocol/   the agent protocol: framing, requests, answers, signed data
internal/agent/      the server: socket, connections, bindings, dispatch, audit
internal/peer/       who connected: uid, audit token, code identity, parents (cgo)
internal/launchd/    the LaunchAgent: property list, install, uninstall, status
```

The packages below `cli` log nothing of their own and return errors on a few sentinels
each. The agent writes the audit log through the logger it is given.

cgo, because there is no other road to the enclave than Apple's frameworks, and with cgo
the C compiler checks every call and constant against Apple's headers. The alternatives
were purego (the same calls declared by hand and checked by nothing, in the one package
where a wrong attribute silently makes a different key, F4), Swift (a new language in the
fleet for nothing the C API lacks) and a helper process (twice the surface).

### Keys

A key is made by the command line, in the enclave: `kSecAttrKeyTypeECSECPrimeRandom`, 256
bits, `kSecAttrTokenIDSecureEnclave`, with an access control of
`kSecAccessControlPrivateKeyUsage` and the class the operator chose:

- `-use locked`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Signs while the
  screen is locked, until the next boot. The bot's choice.
- `-use unlocked`: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

There is no default; the flag is required, so the choice is written in the command.

The key is then stored in the data-protection keychain under the access group
`<team>.org.forkcloser.taciturn`, labelled and tagged with its fingerprint (F13). The
group is read at run time from the process's own `keychain-access-groups` entitlement: the
entry that ends in `org.forkcloser.taciturn`. A process without one, which is any build
run outside the signed bundle, cannot store, load or delete a key and says so. The
keychain tells keys apart by their own attributes, not by the label, so the label's
uniqueness is taciturn's to keep: a lookup precedes every store.

What is on disk, under `~/Library/Application Support/taciturn/keys/` (directory `0700`,
files `0600`, written atomically), is one record per key, `<fingerprint>.json`: the name,
the creation time, the class, the public key in OpenSSH wire form, the policy, and the
fingerprints a rotation links. No key material. The fingerprint is `SHA256:` and the
digest of the public key, the string `ssh-keygen -l` prints. A store that is not private,
or a record that does not agree with its own public key, is refused whole.

The agent reads the store on every request, so a change made by the command line is live
at the next request, with no signal and no second copy of the state.

Deleting a key removes the keychain item, then the record. The public key stays
registered on GitHub until a human removes it, which `key delete` says.

A v0.1 store kept the blob of F3 in `<fingerprint>.blob` beside the record. `key import`
moves such a key into the keychain (F17), proves it with a signature, and only then
deletes the blob file; `doctor` reports a store that still holds one.

### Policy, and the decision the agent makes

Per key, in its record, set by the command line:

```json
{
  "destinations": [
    {"user": "git", "host": "github.com", "hostKeys": ["AAAAC3NzaC1lZDI1NTE5AAAAI…"]}
  ],
  "namespaces": ["git"],
  "peers": [
    "path=/Users/me/Library/Application Support/hermetic/store/pkgs/github_release/github.com/forkcloser/openssh/*/*/*/bin/ssh",
    "path=/Users/me/Library/Application Support/hermetic/store/pkgs/github_release/github.com/forkcloser/openssh/*/*/*/bin/ssh-keygen"
  ]
}
```

- `destinations`: where the key may authenticate. `host` is a label for the listing; the
  host keys, each a public key blob, are what the protocol carries and what the decision
  compares (F8). `key allow NAME -user U -host H -known-hosts FILE` copies the host's keys
  out of a known_hosts file, leaving out one the file marks `@revoked` for the host.
- `namespaces`: the SSHSIG namespaces the key may sign in (`git` for commits and tags).
- `peers`: who may ask. An entry is `any`, or `path=` and a glob matched against the
  peer's executable path (for the main executable of an app bundle, the bundle's
  directory, which is the path Security.framework gives and the audit log records), or a
  code-signing requirement in Apple's requirement language, evaluated on the peer (F9). A
  peer whose path the framework does not give is named by no `path=` entry, whatever the
  glob. The list is the creator's statement, required at
  `key create`; taciturn assumes nothing and ships no default. An entry is checked when it
  is given, as the agent will read it, since the agent treats what it cannot read as
  unsatisfied. A path names a file, and proves nothing about what the file is: it is the
  entry for a client with no signature to name. A requirement names the signer.

What the peer check is worth: it stops a client that speaks the agent protocol itself. A
process that drives an allowed client is bound by the rest of the policy, not by this.

The agent's decision, per connection. The first rule that applies ends it.

1. The peer's uid is not the agent's: the connection is closed.
2. `session-bind` arrives: the host key's signature over the session identifier is
   verified with that key (`x/crypto/ssh`). The binding is recorded, with whether it is
   for forwarding. A signature that does not verify, anything malformed, or a second
   binding that is not the first again, refuses the binding and marks the connection,
   which from then on lists nothing and signs nothing.
3. A connection bound for forwarding lists nothing and signs nothing: a key never
   travels through a forwarded agent.
4. `request-identities`: on an unbound connection, the keys whose policy allows anything;
   on a connection bound for authentication, the keys with a destination that carries the
   bound host key. A retired key is never listed.
5. `sign-request` on a connection bound for authentication: the data must be a
   public-key authentication request, plain or host-bound, for this key and its algorithm,
   with the bound session identifier, naming the bound host key when it is host-bound,
   for a user that a destination with the bound host key allows; and the peer must be one
   the policy names. Then the enclave signs.
6. `sign-request` on an unbound connection: the data must be an SSHSIG request in a
   namespace the policy allows, and the peer one the policy names. An authentication
   request on an unbound connection is refused: a client that does not bind is no OpenSSH
   since 8.9.
7. Any other request, `add`, `remove`, `lock` and the rest, and any extension but
   `session-bind` and `query`: `SSH_AGENT_FAILURE`. The agent is read-only to its clients.
8. A message that cannot be read, or one over 64 KiB, or a connection silent for ten
   seconds: the connection is closed.

Every request leaves one audit record, allowed or refused. A refusal tells the client
nothing but `SSH_AGENT_FAILURE`; the reason is in the log.

What this buys: a process that reaches the socket can make the bot authenticate to
github.com as `git` and sign in the `git` namespace, and nothing else. The repositories'
rulesets then bound what a commit or a push can do.

### Signing

`SecKeyCreateSignature` with `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`: the
framework hashes, the enclave signs. The enclave package returns the pair (r, s); the
agent answers in the `ecdsa-sha2-nistp256` wire form.

### The socket and the process

- A user LaunchAgent, `org.forkcloser.taciturn`, `RunAtLoad`, `KeepAlive`, running
  `taciturn agent` in the foreground. `taciturn install` writes the property list with the
  binary's real path, since launchd starts it with `HOME` and the system `PATH` and
  resolves nothing, and loads it; `uninstall` unloads it. After an upgrade to another
  package directory, `install` again.
- The socket is `~/Library/Application Support/taciturn/agent.sock`, mode `0600`, in a
  directory the agent creates `0700`. A stale socket file is unlinked at start; a lock
  file beside it makes a second agent refuse to start.
- One goroutine per connection, at most 64 served at once, a ten-second idle deadline, a
  64 KiB bound per message. Nothing is shared between connections but the store.
- At SIGINT or SIGTERM the listener closes, the connections in flight finish and the
  socket file goes.

### The audit log

One line of JSON per request, `log/slog`, appended to
`~/Library/Logs/org.forkcloser.taciturn/audit.log` (mode `0600`): the time, the connection,
the peer's pid, path, signing identifier, cdhash, whether its signature was valid, its
parents as far as the system gives them, the request, the key, the binding, the user of an
authentication or the namespace of an SSHSIG request, `allow` or `refuse`, and the rule
that decided. The cdhash and the identifier are read from the code at the peer's path, for
the reader; nothing decides on them or on the parents. The enclave is not asked about
anything a rule refused, so the log is also the record of what was not signed.

`taciturn log` prints it, one line per record; `-follow` keeps reading; `-key NAME` keeps
one key's records; `-json` passes the lines through.

The log is not rotated. On the machine it was written for it grew by about 0.7 MB a day
(25 MB and 26 831 records in five weeks, 2026-11-17).

### The command line

```
taciturn agent [-audit FILE]         serve the socket in the foreground (what the LaunchAgent runs)
taciturn install | uninstall         the user LaunchAgent, org.forkcloser.taciturn
taciturn status                      the LaunchAgent and the socket
taciturn doctor                      the enclave, the store, every key, the agent: one report
taciturn log [-follow] [-json] [-key NAME] [-audit FILE]
taciturn version | help

taciturn key create NAME -use locked|unlocked -peers ENTRY[,ENTRY]
taciturn key list [-format console|json|ssh]
taciturn key show NAME [-format console|json]
taciturn key allow NAME -user USER -host HOST -known-hosts FILE
taciturn key disallow NAME -host HOST
taciturn key peers NAME [-add ENTRY] [-remove ENTRY]
taciturn key sshsig NAME -namespace NS [-remove]
taciturn key delete NAME -yes
taciturn key import
taciturn key rotate NAME
taciturn key retire NAME
taciturn key signers NAME -principal EMAIL
```

A key command takes, for a key that exists, its name or its `SHA256:` fingerprint. The
key commands, `agent` and `doctor` take `-store DIR`; `agent`, `status` and `doctor` take
`-socket PATH`. The exit code is 0 when the command did what it was asked, 1 when it
refused or failed, 2 for a command line it could not read. Every command
but `agent` is a process over the store; none talks to the agent. `create`, `rotate`,
`delete`, `import` and `doctor` reach the enclave and the keychain, which answer only to
the signed bundle, outside any sandbox.

Flags are parsed with the standard `flag` package. The module's dependencies are counted
(below), and a flag parser is not worth one more in a binary that holds signing keys.

### Key rotation

A rotation is two edits to an allowed-signers file that commute, never a deletion: the
successor is added with `valid-after` at its creation, and the retired key gets
`valid-before` at its retirement (`ssh-keygen(1)`, ALLOWED SIGNERS). What the old key
signed before that instant verifies forever; what it signs after is refused.

taciturn owns the local half:

1. `key rotate NAME` makes NAME's successor with the same class and policy, names it
   `NAME` and the current key `NAME@<date>`, links the two, and serves both, so a session
   in the middle of a push keeps working. It prints the successor's public key.
2. The successor is registered on GitHub as an authentication key and a signing key, by a
   human logged in as the key's account. taciturn holds no GitHub credential.
3. `key signers NAME -principal EMAIL` prints the key's allowed-signers line, with its
   window. Where the line goes, and how a fleet of repositories takes it, is not
   taciturn's.
4. `key retire NAME@<date>` stops the agent serving the old key; its record and its
   keychain item stay until `key delete`.

### Threat model

| Adversary | Can | Cannot | Why |
|---|---|---|---|
| Code in a session (sandboxed, same uid) | connect to the socket; get signatures within a key's policy | reach the enclave (F6); see the key (F14); read the store; forward the key | the sandbox, the access group, the policy |
| A process of the user outside any sandbox | everything above; drive an allowed client; read the records, and rewrite one, after which the agent signs what the rewritten policy allows | see the key (F14); use it without the agent; extract it | the access group, the enclave |
| Code signed by the team with the access group | sign with the key, without the agent | extract the key | the enclave |
| Root on this Mac | everything the user can | extract the key | the enclave |
| A disk image, a backup, another Mac | nothing | | the enclave wraps the key for itself |
| A server the bot connects to | learn the public key; be authenticated to only if its host key is in the policy | replay: every signature covers a fresh session identifier | the protocol |
| A forwarded agent on a remote host | nothing: refused at the binding | | rule 3 |

Not addressed, by design: a compromise of the user account outside the sandbox, root, and
a compromise of the sandbox itself. The policy is a file of the user's: the access group
keeps the key behind the agent, and the store's mode and the sessions' sandbox keep the
policy from a session, not from the user's other programs. Whatever is signed, the key's
damage is bounded by the rulesets, and the key is revoked in a click.

A peer entry that is a path is as strong as the path: whoever can write the file there is
the peer. A requirement on a client that loads code at run time (OpenSSH's `ssh` loads a
PKCS#11 provider when told to) admits that code too. Neither gets more than the policy
gives a caller that drives the client.

### Distribution

- taciturn ships as `Taciturn.app/Contents/{Info.plist, embedded.provisionprofile,
  MacOS/taciturn}` (F15), bundle identifier `org.forkcloser.taciturn`, signed with the
  team's Developer ID, hardened runtime, timestamped, with a Developer ID provisioning
  profile (F19). It is a command-line tool that lives in a bundle: launched by path, never
  through Launch Services, so it is not notarized.
- A release is a signed tag, made by `just do release vX.Y.Z`, and limen's Apple release
  lane, `limen-release-apple.yaml`, called at a limen commit from `release.yaml`. The
  lane's `sign` job runs in the `release` environment, which admits `v*` tags only and
  waits for the owner's review; it holds the certificate and the profile with a read-only
  token, runs this project's `package`, and publishes nothing. Its `publish` job holds no
  Apple secret: `verify-assets` checks the archive, the bundle's signature and the version
  it reports, then goreleaser checksums the one asset,
  `taciturn_<version>_darwin_arm64.tar.gz`, signs the checksums keyless with cosign and
  publishes, and GitHub's build provenance attestation covers the asset and
  `checksums.txt`. The signer of both is the lane's workflow, with this repository as the
  source; the commands that verify a release are in the README.
- Machines pin it through hermetic as a `github_release` package with its attestation and
  checksum, in limen-install's registry; the LaunchAgent runs the package's real path.

### Testing

The book's shape: for each package a contract in `contract_test.go`, a bounded walk, and a
fuzz target where bytes are decoded; black-box, through the package's own surface.

- `protocol`: every message at its edges and truncated at every field, round trips, and
  x/crypto's encoder and decoder as an oracle written by other hands.
- `policy`: the decision table as a bounded walk over binding state, request shape and
  policy, and a fuzz target against the rules as this document states them.
- `keystore`: every sequence of up to four writes over two keys against a model; modes,
  corruption, bounds.
- `agent`: a real client over a temporary socket for listing, binding and every refusal;
  OpenSSH's own `ssh-add` and `ssh-keygen` at the socket.
- `cli`: through its one entry point.
- The hardware lane, `just test-hardware`, on a Mac outside any sandbox: it builds the
  test binaries of the packages `hack/test-hardware.sh` names, wraps each in a bundle
  signed with the Apple Development identity and a development profile, and runs it. It
  holds what needs the enclave and the entitlement: make, store, load in another process,
  sign and verify, the import of F17, and the agent end to end, with forkcloser/openssh's
  `sshd` on the loopback and its `ssh` pinned to the agent's key: a named destination
  logs in on a host-bound signature, an unnamed host key gets an empty listing, and a
  forwarded agent sees nothing. Elsewhere those tests skip and say why.
- The locked-screen claim (F7, F18) is a manual procedure, in the README, run at every
  macOS major.

### Dependencies

`github.com/mycophonic/primordium` (atomic writes, advisory locks, the socket path bound,
the home directory, output formats), `golang.org/x/crypto` (SSH keys and signatures, host-key verification),
`golang.org/x/sys`. The lint overlay's depguard allows these three and the standard
library.

## Decisions

Each was put with its alternatives; the answer and its reason stand here.

2026-10-12:

2. **The bot key's class is `AfterFirstUnlockThisDeviceOnly`**: it signs while the screen
   is locked, until reboot, so unattended sessions finish their pushes.
3. **Who may ask is stated per key at creation, with no default.** `key create` refuses
   without `-peers`; the installer that sets the client up names it. A default that a
   release changes is a policy nobody stated. `-peers any` turns the check off for a key.
4. **An authentication signature on an unbound connection is refused.** Only SSHSIG
   requests are answered unbound.
5. **An own protocol loop**, not `x/crypto/ssh/agent.ServeAgent`: a 64 KiB bound, a
   dispatch that refuses by default, binding state per connection.
6. **The names**: `taciturn`, `org.forkcloser.taciturn`,
   `~/Library/Application Support/taciturn/{keys,agent.sock}`,
   `~/Library/Logs/org.forkcloser.taciturn/`.
7. **forkcloser/openssh is the bot's only ssh**, with P-256 (F2).
9. **GitHub key registration stays manual**: no token of the bot at rest anywhere.
10. **Rotation: taciturn local, the fleet's files elsewhere**, on the allowed-signers
    validity window, never a deletion.
11. **cgo, not purego.**

2026-10-13:

12. **Keys live in the data-protection keychain under `<team>.org.forkcloser.taciturn`**,
    permanent, labelled by fingerprint. The record file stays; no blob is written, and
    the agent exports no key material (F16). This replaced the blob file of v0.1, which
    was the key to any process that could read it (F3).
13. **taciturn ships as `Taciturn.app`**, Developer ID signed with an embedded Developer
    ID provisioning profile, launched by path (F13, F15).
14. **The release is signed in CI and not notarized**: the bundle is launched by path,
    never through Launch Services. Where the signing credentials live is decision 18.
15. **Existing keys are imported, not rotated** (F17): `taciturn key import`, once per
    machine.
16. **The access group is read from the entitlement at run time**; no team identifier is
    in the source.
17. **Peers are named by requirement once the client is signed**: forkcloser/openssh's
    binaries carry a Developer ID signature since v10.6.1.6, and a key's path entries are
    the operator's to replace.

2026-11-01:

18. **The release runs on limen's Apple lane, and the signing secrets are the `release`
    environment's.** A repository secret reaches any workflow run in the repository's own
    context that names it; the environment's reach a run on a `v*` tag after the owner's
    review, in a job that publishes nothing.

Recorded 2026-11-17:

19. **The standard `flag` package**, not a parser from outside the standard library.
