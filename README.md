# taciturn

An ssh-agent for keys that live in the Mac's Secure Enclave, built for processes that
work unattended: a Claude Code session pushing and signing as a bot identity, from
inside its sandbox, with no touch and no screen to unlock.

What it is:

- **One binary, `taciturn`, shipped as `Taciturn.app`**: the agent (a user LaunchAgent
  on a fixed socket) and the command line that creates, lists, inspects, constrains,
  rotates and deletes keys. The bundle is signed with the team's Developer ID and carries
  the provisioning profile that grants its keychain access group.
- **Keys that never exist outside the enclave.** ECDSA P-256, the one curve the enclave
  implements. The enclave holds the key; its reference lives in the data-protection
  keychain under the bundle's access group, visible to nothing but code signed by the
  team with that group. The record on disk carries the policy and the public key, no key
  material. A key may sign while the screen is locked, until the next reboot.
- **A signature only for what a key is allowed to do.** The agent reads the destination
  OpenSSH binds to a connection (`session-bind@openssh.com`), the user in the
  authentication request, and the namespace of an `ssh-keygen -Y sign` request, and
  answers only within the key's policy; never through a forwarded agent.
- **Only the clients a key names.** Each key states, at creation, which processes may
  ask it to sign, by executable path or code-signing requirement; taciturn assumes
  nothing and ships no default.
- **Every use recorded**: which process, which key, which destination, allowed or refused.

darwin/arm64 only. The design, the facts it rests on and the decisions behind it are in
[docs/design.md](docs/design.md).

## Install

A release is one archive, `taciturn_<version>_darwin_arm64.tar.gz`, holding `Taciturn.app`.
Unpack it where it will stay, then, from a shell outside any sandbox:

```sh
Taciturn.app/Contents/MacOS/taciturn install
Taciturn.app/Contents/MacOS/taciturn doctor
```

`install` writes the LaunchAgent `org.forkcloser.taciturn` with the binary's real path and
loads it; run it again after moving or upgrading the bundle. `doctor` checks the enclave,
the keychain access group, the store, every key, the LaunchAgent and the socket, one line
each, and exits 1 when one is wrong. `uninstall` unloads the agent; the keys stay.

The agent serves `~/Library/Application Support/taciturn/agent.sock` and writes its audit
log to `~/Library/Logs/org.forkcloser.taciturn/audit.log`.

## Use

```sh
taciturn key create bot -use locked -peers 'path=/opt/ssh/bin/ssh,path=/opt/ssh/bin/ssh-keygen'
taciturn key allow bot -user git -host github.com -known-hosts ~/.ssh/known_hosts
taciturn key sshsig bot -namespace git
taciturn key list -format ssh
```

That is a key that signs while the screen is locked, for the two programs named, to
authenticate as `git` to the server whose host keys `known_hosts` holds for github.com,
and to sign in the `git` namespace, which is commits and tags. The last command prints the
public key in the form GitHub and `authorized_keys` take.

A client is pointed at the socket: `ssh` with `IdentityAgent` and
`PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256`, `ssh-keygen -Y sign` with `SSH_AUTH_SOCK`.
`taciturn log` prints what was asked and what was answered; `taciturn help` lists every
command.

## Verifying a release

Since v0.4.0 a release is made by limen's Apple release lane, a reusable workflow, which
is therefore the signer; the source is this repository. With the three release assets in
the current directory:

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/farcloser/limen/\.github/workflows/limen-release-apple\.yaml@.*' \
  --certificate-github-workflow-repository forkcloser/taciturn \
  checksums.txt
shasum -a 256 -c checksums.txt
```

or, without cosign:

```sh
gh attestation verify taciturn_<version>_darwin_arm64.tar.gz --repo forkcloser/taciturn \
  --signer-workflow farcloser/limen/.github/workflows/limen-release-apple.yaml
```

The bundle itself answers to `codesign --verify --deep --strict Taciturn.app`, and
`codesign -d --verbose=2 Taciturn.app` names the Developer ID that signed it. Releases
before v0.4.0 were signed by this repository's own `release.yaml`.

## The hardware tests

`just test` runs everywhere and skips what needs the enclave. `just test-hardware` runs
those tests on a Mac outside any sandbox, from a bundle signed with an Apple Development
identity and a development provisioning profile for `org.forkcloser.taciturn`
(`APPLE_PROVISIONING_PROFILE_PATH`, by default
`~/Library/MobileDevice/Provisioning Profiles/taciturn-dev.provisionprofile`). Without the
profile the keychain tests skip and say so.

## The locked screen, by hand

That a key made with `-use locked` signs while the screen is locked, and one made with
`-use unlocked` does not, is the enclave's behaviour and cannot be tested unattended. It is
checked by hand at every macOS major. With a key `NAME` that allows the `git` namespace
and an `ssh-keygen` it names as a peer:

```sh
taciturn key list -format ssh | grep ' NAME$' > /tmp/key.pub
( sleep 30
  echo locked | SSH_AUTH_SOCK="$HOME/Library/Application Support/taciturn/agent.sock" \
    ssh-keygen -Y sign -n git -f /tmp/key.pub > /tmp/locked.sig 2> /tmp/locked.err
  echo "$?" > /tmp/locked.exit ) &
```

Lock the screen within the thirty seconds (Control-Command-Q), wait a minute, unlock.
For a `locked` key, `/tmp/locked.exit` holds 0 and `/tmp/locked.sig` a signature. For an
`unlocked` key the exit is not 0, and `taciturn log -json -key NAME` ends with the request
refused and the enclave's error.
