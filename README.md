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
  keychain under the bundle's access group, readable by nothing but code signed by the
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
