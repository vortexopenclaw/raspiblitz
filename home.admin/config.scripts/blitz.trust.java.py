#!/usr/bin/env python3
"""Remove only Debian's two October 2026 incident anchors from Java cacerts.

Uses keytool's public-certificate listing, never exports or decrypts private keys.
Non-default store passwords require separately reviewed administrator remediation.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys

DENIED = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
}
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def keytool(store, *args):
    result = subprocess.run([
        "keytool", "-J-Duser.language=en", "-J-Duser.country=US",
        *args, "-keystore", str(store), "-storepass", "changeit",
    ], capture_output=True, text=True, env={**os.environ, "LC_ALL": "C.UTF-8"})
    if result.returncode:
        raise RuntimeError("keytool failed; check store permissions, password, and JRE")
    return result.stdout


def inventory(text):
    count = re.search(r"Your keystore contains (\d+) entr(?:y|ies)", text)
    if not count:
        raise RuntimeError("Cannot validate keytool entry count")
    entries = {}
    for block in re.split(r"(?m)^Alias name: ", text)[1:]:
        alias, _, details = block.partition("\n")
        kind = re.search(r"(?m)^Entry type: (\S+)\s*$", details)
        certs = PEM.findall(details)
        if not alias or alias.startswith("-") or alias in entries or not kind or not certs:
            raise RuntimeError("Ambiguous keytool entry; refusing modification")
        if kind[1] not in {"trustedCertEntry", "PrivateKeyEntry"}:
            raise RuntimeError("Unsupported keystore entry type")
        if kind[1] == "trustedCertEntry" and len(certs) != 1:
            raise RuntimeError("Ambiguous trusted certificate entry")
        hashes = tuple(hashlib.sha256(ssl.PEM_cert_to_DER_cert(c)).hexdigest() for c in certs)
        entries[alias] = (kind[1], hashes)
    if len(entries) != int(count[1]):
        raise RuntimeError("Keystore inventory count mismatch")
    return entries


def remediate(store, update=False):
    before = inventory(keytool(store, "-list", "-rfc"))
    targets = []
    for alias, (kind, hashes) in before.items():
        if DENIED.intersection(hashes):
            if kind != "trustedCertEntry":
                raise RuntimeError("Incident certificate in a private-key entry; manual review required")
            targets.append(alias)
    if targets and not update:
        raise RuntimeError(f"Java store still trusts {len(targets)} incident anchor entries")
    for alias in targets:
        # Refuse a changed inventory instead of deleting a concurrently replaced entry.
        current = inventory(keytool(store, "-list", "-rfc"))
        expected = {k: v for k, v in before.items() if k not in targets[:targets.index(alias)]}
        if current != expected:
            raise RuntimeError("Keystore changed during remediation; stop concurrent maintenance")
        keytool(store, "-delete", "-alias", alias)
    after = inventory(keytool(store, "-list", "-rfc"))
    expected = {k: v for k, v in before.items() if k not in targets}
    if after != expected:
        raise RuntimeError("Java postcondition failed: unrelated public entries changed")
    print(f"Java incident anchors absent; {len(targets)} removed, {len(after)} entries preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "update"))
    parser.add_argument("--keystore", type=Path, default=Path("/etc/ssl/certs/java/cacerts"))
    args = parser.parse_args()
    if not args.keystore.is_file():
        raise RuntimeError("Java cacerts missing; repair the vendor package first")
    remediate(args.keystore, args.mode == "update")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"FAIL - {exc}", file=sys.stderr)
        sys.exit(1)
