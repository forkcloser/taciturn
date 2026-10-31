#!/usr/bin/env bash
#
# Delete the release lane's signing keychain and provisioning profile, the
# files TACITURN_SIGNING_KEYCHAIN and TACITURN_PROFILE name. goreleaser runs
# it as the post-build hook after hack/bundle.sh has signed the bundle, so
# the identity is gone before anything is archived or published; the release
# workflow runs it again as its last step, for a run that failed earlier.
# TACITURN_SIGNING_KEYCHAIN is set by the workflow alone: without it nothing
# is deleted, so a local dry run with TACITURN_PROFILE in the shell keeps
# its profile.
set -euo pipefail
keychain="${TACITURN_SIGNING_KEYCHAIN:-}"
if [ -z "$keychain" ]; then
  exit 0
fi
if [ -f "$keychain" ]; then
  security delete-keychain "$keychain"
fi
profile="${TACITURN_PROFILE:-}"
if [ -n "$profile" ] && [ -f "$profile" ]; then
  rm -f "$profile"
fi
