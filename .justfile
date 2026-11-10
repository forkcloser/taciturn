# This file is the project's own. Keep the import: it mounts every shared
# limen task under `just do ...`.
import '.limen/just/main.just'

# The agent is cgo against Security.framework: every Go task knows it
# (book/recipes.md, GO_CGO).
export GO_CGO := '1'

# The FIRST recipe defined here becomes `just`'s default.
lint: do::lint::go::default do::lint::go::deadcode do::lint::default
fix: do::fix::go::default do::fix::default
test: do::test::go::unit do::test::go::race
# The security workflow runs `just security`.
security: do::security::default

# The hardware lanes, on a Mac outside any sandbox: the enclave and the
# keychain, through test binaries wrapped in a development bundle
# (hack/test-hardware.sh, docs/design.md "Testing").
test-hardware:
    hack/test-hardware.sh

# The Apple release lane's two recipes (book/releasing.md): `package` runs in
# the lane's sign job with the identity in APPLE_SIGN_IDENTITY and the profile
# at APPLE_PROVISIONING_PROFILE_PATH, `verify-assets` as goreleaser's before
# hook in the publish job, which holds neither. Locally both run ad hoc:
# `just package 0.0.0 && just do release --local --dry-run`.
#
# One asset, taciturn_<version>_darwin_arm64.tar.gz, carrying Taciturn.app and
# nothing else: the name and the layout limen-install's registry entry reads.
# tar, not ditto: the bundle has no resource fork, and the archive is the one
# hermetic unpacks.
package version:
    #!/usr/bin/env bash
    set -euo pipefail
    version='{{ version }}'
    BUILD_GO_LDFLAGS="-X main.version=${version}" just do build go release
    TACITURN_BUNDLE_VERSION="$version" hack/bundle.sh .build/taciturn .build/bundle
    just do apple-verify-signed .build/bundle/Taciturn.app
    mkdir -p .build/assets
    asset=".build/assets/taciturn_${version}_darwin_arm64.tar.gz"
    rm -f "$asset"
    tar -C .build/bundle -czf "$asset" Taciturn.app
    echo "package: $asset"

# What .build/assets/ holds is one archive of the version, and the bundle in
# it is signed (Developer ID and timestamped on a release run, ad hoc
# otherwise) and reports that version.
verify-assets version:
    #!/usr/bin/env bash
    set -euo pipefail
    version='{{ version }}'
    asset=".build/assets/taciturn_${version}_darwin_arm64.tar.gz"
    [ -f "$asset" ] || { echo "verify-assets: $asset does not exist" >&2; exit 1; }
    count=$(find .build/assets -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
    [ "$count" = 1 ] || { echo "verify-assets: .build/assets holds $count entries, want the one archive" >&2; exit 1; }
    unpacked="$(mktemp -d "${TMPDIR:-/tmp}/taciturn-verify.XXXXXX")"
    trap 'rm -rf "$unpacked"' EXIT
    tar -C "$unpacked" -xzf "$asset"
    [ -d "$unpacked/Taciturn.app" ] || { echo "verify-assets: $asset does not carry Taciturn.app at its root" >&2; exit 1; }
    just do apple-verify-signed "$unpacked/Taciturn.app"
    reported=$("$unpacked/Taciturn.app/Contents/MacOS/taciturn" version)
    [ "$reported" = "taciturn $version" ] || { echo "verify-assets: the binary reports '$reported', want 'taciturn $version'" >&2; exit 1; }
    bundled=$(plutil -extract CFBundleShortVersionString raw -o - "$unpacked/Taciturn.app/Contents/Info.plist")
    [ "$bundled" = "$version" ] || { echo "verify-assets: Info.plist says $bundled, want $version" >&2; exit 1; }
    echo "verify-assets: $asset carries Taciturn.app $version, signed"
