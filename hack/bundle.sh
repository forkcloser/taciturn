#!/usr/bin/env bash
#
# Wrap a taciturn binary in Taciturn.app and sign it (docs/design.md, v0.2):
#
#   hack/bundle.sh <binary> <output directory> [<executable name>]
#
# The bundle is <output directory>/Taciturn.app with Contents/Info.plist,
# Contents/MacOS/<name> and, when TACITURN_PROFILE names a provisioning
# profile, Contents/embedded.provisionprofile. With TACITURN_SIGN_IDENTITY
# set (a codesign identity: "Developer ID Application" in the release lane,
# "Apple Development" for the hardware tests) the bundle is signed with the
# entitlements the profile grants: application-identifier, team-identifier
# and keychain-access-groups, all read from the profile so no team
# identifier lives in the tree. Without an identity the bundle is left
# unsigned, which is what a dry run on a machine without a certificate gets.
set -euo pipefail

binary="${1:-}"
out="${2:-}"
name="${3:-taciturn}"
if [ -z "$binary" ] || [ -z "$out" ]; then
  echo "usage: hack/bundle.sh <binary> <output directory> [<executable name>]" >&2
  exit 2
fi
[ -x "$binary" ] || { echo "hack/bundle.sh: $binary is not an executable" >&2; exit 2; }

identifier="org.forkcloser.taciturn"
app="$out/Taciturn.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$binary" "$app/Contents/MacOS/$name"
chmod 0755 "$app/Contents/MacOS/$name"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$identifier</string>
	<key>CFBundleName</key>
	<string>Taciturn</string>
	<key>CFBundleExecutable</key>
	<string>$name</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleVersion</key>
	<string>${TACITURN_BUNDLE_VERSION:-0}</string>
	<key>CFBundleShortVersionString</key>
	<string>${TACITURN_BUNDLE_VERSION:-0}</string>
	<key>LSMinimumSystemVersion</key>
	<string>15.0</string>
	<key>LSBackgroundOnly</key>
	<true/>
</dict>
</plist>
EOF

profile="${TACITURN_PROFILE:-}"
identity="${TACITURN_SIGN_IDENTITY:-}"

if [ -z "$identity" ]; then
  # No identity: an ad hoc signature, so the bundle has the shape a signed
  # one has (Contents/_CodeSignature) and a dry run archives the same tree
  # a release does. It carries no entitlements and reaches no keychain.
  codesign --force --sign - "$app"
  echo "hack/bundle.sh: $app assembled, signed ad hoc (TACITURN_SIGN_IDENTITY unset)"
  exit 0
fi

[ -f "$profile" ] || { echo "hack/bundle.sh: TACITURN_PROFILE must name the provisioning profile" >&2; exit 2; }
cp "$profile" "$app/Contents/embedded.provisionprofile"

# The entitlements come from the profile: what it grants is what the bundle
# claims, and the application identifier is the team's prefix plus the
# bundle identifier.
plist="$(security cms -D -i "$profile")"
# plutil's key path separates on dots; the dots in the entitlement's own
# name are escaped.
appid="$(printf '%s' "$plist" | plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - -)"
team="${appid%%.*}"
case "$appid" in
  "$team.$identifier") ;;
  *) echo "hack/bundle.sh: the profile is for $appid, not $identifier" >&2; exit 2 ;;
esac

entitlements="$(mktemp "${TMPDIR:-/tmp}/taciturn-entitlements.XXXXXX")"
trap 'rm -f "$entitlements"' EXIT
cat > "$entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key>
	<string>$appid</string>
	<key>com.apple.developer.team-identifier</key>
	<string>$team</string>
	<key>keychain-access-groups</key>
	<array>
		<string>$appid</string>
	</array>
</dict>
</plist>
EOF

# The timestamp flag has three states, since codesign rejects an empty URL:
# unset or empty, Apple's timestamp server (the release); "none", no
# timestamp (the hardware tests, offline); anything else, that server.
case "${TACITURN_SIGN_TIMESTAMP:-}" in
  "") timestamp="--timestamp" ;;
  none) timestamp="--timestamp=none" ;;
  *) timestamp="--timestamp=$TACITURN_SIGN_TIMESTAMP" ;;
esac

codesign --force --options runtime "$timestamp" \
  --sign "$identity" --entitlements "$entitlements" "$app"
codesign --verify --deep --strict "$app"
echo "hack/bundle.sh: $app signed by \"$identity\" for $appid"
