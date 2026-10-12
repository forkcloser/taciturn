# taciturn

An ssh-agent for keys that live in the Mac's Secure Enclave, built for processes that
work unattended: a Claude Code session pushing and signing as a bot identity, from
inside its sandbox, with no touch and no screen to unlock.

What it is:

- **One binary, `taciturn`**: the agent (a user LaunchAgent on a fixed socket) and the
  command line that creates, lists, inspects, constrains, rotates and deletes keys.
- **Keys that never exist outside the enclave.** ECDSA P-256, the one curve the enclave
  implements; what is stored on disk is an enclave-wrapped blob that unwraps nowhere else.
- **A signature only for what a key is allowed to do.** The agent reads the destination
  OpenSSH binds to a connection (`session-bind@openssh.com`), the user in the
  authentication request, and the namespace of an `ssh-keygen -Y sign` request, and
  answers only within the key's policy; never through a forwarded agent.
- **Every use recorded**: which process, which key, which destination, allowed or refused.

darwin/arm64 only. The design, the facts it rests on and the decisions behind it are in
[docs/design.md](docs/design.md).
