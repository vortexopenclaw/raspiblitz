#!/usr/bin/env bash
# Independent Python stores do not inherit removals from ca-certificates.
# Run as the venv owner. Never rewrite bundles or override dependency constraints.
set -euo pipefail
mode=${1:?Usage: blitz.python-trust.sh pip|app PYTHON [BOOTSTRAP_CA_FILE]}
python=${2:?Specify the venv Python executable}
bootstrap_ca=${3:-/etc/ssl/certs/ca-certificates.crt}
case "$mode" in
  pip|app) ;;
  *) echo "Unknown trust check mode" >&2; exit 1 ;;
esac

check_bundle() {
  "$python" - "$1" <<'PY'
import hashlib
import pathlib
import re
import ssl
import sys

mode = sys.argv[1]
if mode == "pip":
    from pip._vendor import certifi
    bundle = certifi.where()
elif mode == "app":
    import certifi
    bundle = certifi.where()
else:
    bundle = mode
blocked = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
}
pem = pathlib.Path(bundle).read_text(encoding="ascii")
certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
if not certs:
    sys.exit("No trust anchors found; refusing to continue")
roots = {hashlib.sha256(ssl.PEM_cert_to_DER_cert(c)).hexdigest() for c in certs}
if roots & blocked:
    sys.exit("Affected emSign anchor remains in Python trust store; update its owner package")
# Parse the complete file, not only the matching PEM blocks.
ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(bundle)
print("Python trust bundle check passed")
PY
}

if [ "$mode" = pip ]; then
  check_bundle "$bootstrap_ca"
  # --cert alone is additive with modern pip's truststore context. Legacy mode
  # makes this bootstrap use ONLY the reviewed system bundle, including local CAs.
  "$python" -m pip --use-deprecated=legacy-certs --cert "$bootstrap_ca" \
    install --upgrade 'pip>=26.2.2'
fi
check_bundle "$mode"
