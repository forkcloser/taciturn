#!/usr/bin/env bash
#
# The hardware lanes, on a Mac, outside any sandbox (docs/design.md,
# "Testing", v0.2): the enclave and agent tests need the Secure Enclave and,
# for the keychain, the keychain-access-groups entitlement, which only a
# signed bundle with a provisioning profile carries. Each package's test
# binary is built, wrapped in a bundle signed with the Apple Development
# identity and the development profile, and run from inside it; the tests
# skip what the process cannot do and say so.
#
#   just test-hardware
#
# TACITURN_PROFILE names the development profile (default
# ~/Library/MobileDevice/Provisioning Profiles/taciturn-dev.provisionprofile),
# TACITURN_SIGN_IDENTITY the identity ("Apple Development" by default).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/build/hardware"
export TACITURN_PROFILE="${TACITURN_PROFILE:-$HOME/Library/MobileDevice/Provisioning Profiles/taciturn-dev.provisionprofile}"
export TACITURN_SIGN_IDENTITY="${TACITURN_SIGN_IDENTITY:-Apple Development}"
# No timestamp server for a test bundle: offline, and nothing verifies it later.
export TACITURN_SIGN_TIMESTAMP="${TACITURN_SIGN_TIMESTAMP:-none}"

# The local-sshd leg runs forkcloser/openssh's sshd and ssh from one install
# directory; hermetic knows where the pinned fork's ssh lives.
if [ -z "${TACITURN_OPENSSH:-}" ] && command -v hermetic > /dev/null 2>&1; then
  fork_ssh="$(hermetic which ssh 2> /dev/null || true)"
  if [ -n "$fork_ssh" ] && [ -x "$(dirname "$fork_ssh")/../sbin/sshd" ]; then
    TACITURN_OPENSSH="$(cd "$(dirname "$fork_ssh")/.." && pwd)"
    export TACITURN_OPENSSH
  fi
fi
if [ -z "${TACITURN_OPENSSH:-}" ]; then
  echo "test-hardware: TACITURN_OPENSSH is unset and hermetic has no forkcloser/openssh; the local-sshd leg will skip" >&2
fi

if [ ! -f "$TACITURN_PROFILE" ]; then
  echo "test-hardware: no development profile at $TACITURN_PROFILE; the keychain tests will skip" >&2
  unset TACITURN_SIGN_IDENTITY
fi

mkdir -p "$out"
status=0
for pkg in enclave agent; do
  dir="$out/$pkg"
  rm -rf "$dir"
  mkdir -p "$dir"
  (cd "$root" && CGO_ENABLED=1 go test -c -o "$dir/$pkg.test" "./internal/$pkg/")
  "$root/hack/bundle.sh" "$dir/$pkg.test" "$dir" "$pkg.test" > /dev/null
  echo "=== $pkg, from $dir/Taciturn.app"
  (cd "$root/internal/$pkg" && "$dir/Taciturn.app/Contents/MacOS/$pkg.test" -test.v "$@") || status=1
done
exit "$status"
