# Public-download TLS regression checks

Run `python3 test/public-download-tls.py` with Python 3, Bash, wget, and OpenSSL installed. The tests never run installers, sudo, service operations, or package upgrades. Temporary fixtures honor `TMPDIR`.

The tests extract the actual key-download commands from the LND, Pool, and chantools installers, and the authorized-key download from the amd64 packer initializer. Each executes real wget against an ephemeral local HTTPS server with an untrusted self-signed certificate. The negative case must report a certificate error and exit before a continuation marker. An explicit test-only CA enables the positive control. This does not modify system trust.

The Sphinx readiness block is extracted and exercised with a real local TLS endpoint for both direct and stubbed torsocks routing. Public-CA, Tor, and local-network modes must reject an untrusted HTTPS certificate; only the two explicit self-signed modes accept it. All modes must accept the test-only CA. The torsocks stub does not test Tor transport. Plain HTTP and onion transport are unchanged.

Verification on 2026-10-29 used macOS and Homebrew wget 1.25.0. All three test methods passed. Normal, CA-verified wget GET requests returned HTTP 200 for both Keybase signer-key endpoints, the LND roasbeef and ziggie1984 keys on raw.githubusercontent.com, and the packer Vagrant key URL after its HTTPS redirect. These are point-in-time host TLS checks, not artifact authenticity, Debian hardware, or full application-installation tests.

The patch preserves existing signature and checksum logic; it does not certify those implementations. It makes a failed key download fatal rather than continuing with cached state. This complements current CA packages after the eMudhra SSL certificate compromise but cannot replace vendor trust updates or guarantee universal incident coverage. Existing local peer readiness calls and application-specific certificate paths are intentionally not globally rewritten.
