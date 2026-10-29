#!/bin/bash

# Vendor-managed trust only. Policy and limitations: test/TRUST-AUDIT.md.
if [ "$#" -ne 1 ] || { [ "$1" != update ] && [ "$1" != check ]; }; then
  echo "Usage: blitz.trust.sh [update|check]"
  exit 1
fi

fail() {
  echo "FAIL - $* Check security repositories, package pins/holds, and runtime overrides." >&2
  exit 1
}

installed() {
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = installed ]
}

if [ "$1" = update ]; then
  packages=(ca-certificates)
  if installed nodejs; then packages+=(nodejs); fi
  # Do not override holds/pins or accept a partial index refresh.
  sudo apt-get -o APT::Update::Error-Mode=any update || fail "APT index refresh failed."
  sudo apt-get install --only-upgrade -y "${packages[@]}" || fail "Trust package upgrade failed."
  sudo update-ca-certificates --fresh || fail "Trust bundle refresh failed."
fi

# Offline fail-closed postconditions, not network probes or package-command success.
# Debian DLA-4845-1 / DSA-6572-1 remove ECC G3 AND the AAA cross-sign route.
ID='' VERSION_ID=''
# shellcheck disable=SC1091
source /etc/os-release || fail "Cannot identify the OS."
case "$ID:$VERSION_ID" in
  debian:12) minimum='20250419~deb12u2' ;;
  debian:13) minimum='20250419+deb13u1' ;;
  *) fail "No reviewed CA package baseline for $ID $VERSION_ID." ;;
esac
installed ca-certificates || fail "ca-certificates is not installed."
ca_version=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null)
dpkg --compare-versions "$ca_version" ge "$minimum" || fail "ca-certificates $ca_version needs >= $minimum."

# Official October 21, 2026 security releases, only on reviewed supported lines.
# Check the executable too: a PATH override must not hide behind a fixed package.
if installed nodejs || command -v node >/dev/null 2>&1; then
  node_version=$(node -v 2>/dev/null) || fail "Installed Node.js cannot run."
  [[ "$node_version" =~ ^v(22|24|26)\.[0-9]+\.[0-9]+$ ]] || fail "Unsupported Node.js $node_version."
  case "$node_version" in
    v22.*) minimum=22.23.4 ;;
    v24.*) minimum=24.22.1 ;;
    v26.*) minimum=26.12.1 ;;
  esac
  dpkg --compare-versions "${node_version#v}" ge "$minimum" || fail "Node.js $node_version needs >= $minimum on its major line."
fi

echo "Vendor trust package baselines verified. Restart consumers after updates."
echo "Independent application bundles and explicit CA overrides need separate checks."
