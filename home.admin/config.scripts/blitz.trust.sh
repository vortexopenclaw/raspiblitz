#!/bin/bash

# Refresh vendor-managed trust without editing certificate lists or app settings.
# Node.js has a separate bundled store, so refresh its package when installed too.
if [ "$#" -ne 1 ] || [ "$1" != "update" ]; then
  echo "Usage: blitz.trust.sh update"
  exit 1
fi

packages=(ca-certificates)
if [ "$(dpkg-query -W -f='${Status}' nodejs 2>/dev/null)" = "install ok installed" ]; then
  packages+=(nodejs)
fi

# A partial index refresh must not silently leave us using stale security data.
sudo apt-get -o APT::Update::Error-Mode=any update || exit 1
sudo apt-get install --only-upgrade -y "${packages[@]}" || exit 1
sudo update-ca-certificates --fresh || exit 1

echo "Vendor trust packages refreshed. Restart consumers to load updated trust."
echo "Independent application bundles and explicit CA overrides need separate checks."
