# Python protection after the eMudhra certificate compromise

The OS trust update does not remove compromised eMudhra trust paths from
Python bundles. BlitzAPI owns its application dependency locks in
[fusion44/blitz_api](https://github.com/fusion44/blitz_api), referenced by
`build_sdcard.sh` and `blitz.web.api.sh`. There is no public
`raspiblitz/blitz_api` repository. The script is `blitz.web.api.sh`, not
`blitz.api.sh`.

## Focused changes

BlitzAPI updates only certifi in `requirements.txt` and `uv.lock`, from
2026.6.17 to 2026.10.19. No other dependency is changed. Older deployed
BlitzAPI releases can receive the same certifi-only package update without
installing the current development branch's unrelated requirements.

RaspiBlitz updates pip independently and checks the resulting vendored
bundle. `blitz.python-trust.sh pip PYTHON [BOOTSTRAP_CA_FILE]` uses the reviewed
system CA bundle for bootstrap, including its local anchors, and requests
`pip>=26.2.2`. It does not bypass package constraints or edit any trust bundle.
An incompatible pip pin, stale index, unsafe bootstrap bundle, or affected
post-install bundle stops the operation. For a deliberately separate custom
CA bundle, explicitly supply that reviewed bundle as the third argument.

`--cert` alone does not remove pip's already-loaded vendored roots. The
bootstrap combines `--use-deprecated=legacy-certs` with `--cert` to select
only the supplied bundle. Normal pip truststore operation resumes after the
upgrade. Both switches were exercised with pip 26.0.1 and 26.2.2.

BlitzAPI install/update checks its standalone certifi before starting services,
and repairs pip even if the application commit has not changed. Failures leave
services stopped rather than restarting with an affected bundle. The fixed
BlitzAPI dependency lock must be available before using this fail-closed path.
JoinMarket's installer repairs pip on both new and already-installed paths;
its OS-root Twisted runtime does not need an application certifi dependency.
Updates performed directly inside external JoininBox are outside this hook;
rerun the pip helper after such updates.

## Verified release artifacts

The PyPI release JSON and downloaded wheel SHA-256 values were checked directly:

* [certifi 2026.10.19](https://pypi.org/pypi/certifi/2026.10.19/json), Python >=3.7,
  wheel SHA-256 `42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b`.
* [pip 26.2.2](https://pypi.org/pypi/pip/26.2.2/json), Python >=3.10,
  wheel SHA-256 `fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70`.
  Its wheel's `pip/_vendor/vendor.txt` explicitly lists certifi 2026.10.19.
  This is a verified fixed release, not a claim that every earlier pip release
  is affected or that installing standalone certifi fixes pip.

Both wheels omit these affected root DER SHA-256 fingerprints:

* `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`
* `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4`

## Local regression evidence

The local macOS CPython 3.12 test venv used the node's requests 2.32.5 and httpx
0.28.1 versions, with actual adapter/transport defaults and pip's real
`_create_truststore_ssl_context`. Before remediation, certifi 2025.4.26 and
pip 26.0.1 each accepted 8 of the 16 unique published incident chains offline.
Updating standalone certifi alone reduced requests/httpx to zero accepted
chains while pip still accepted eight. Updating pip separately reduced all
three consumers to zero. Rejections were issuer-validation failures, with
OpenSSL 3's default CA path/store disabled.

The fixed requests, httpx, and actual pip session each rejected all 14 public
incident hosts with certificate-validation errors and accepted a verified
TLS positive control at pypi.org. The two rollover fixtures have no live hosts
and were verified offline only. Explicit roots from pip's underlying context
were exported for offline tests; native OS trust is not fully enumerable on
all platforms. Live pip probes exercised the full native-plus-vendor context.

The actual bootstrap upgraded pip 26.0.1 to 26.2.2 while standalone certifi
remained unchanged. An incompatible `pip==26.0.1` constraint failed rather
than being overridden. An affected bootstrap bundle was refused. An extra
local anchor in a reviewed bootstrap bundle remained byte-for-byte unchanged
across the real bootstrap. This checks bundle preservation, not a custom-CA
server handshake. Shell syntax checks passed. BlitzAPI's frozen lock installed
successfully; its three standalone client-root tests and Ruff checks passed.

No production packages, services, or source files were changed. Local tests
are not evidence that production services have restarted with these packages.
The existing OS/Node and Bitcoin Core/LND changes are separate.

## Reproduce

Download the public chain archive linked from
<https://emudhra.we-have-a-problem.com/> and use its `chains` directory.
Run these in an isolated venv, not on a production service:

```sh
python tests/python-trust-regression.py --chains "$CHAINS" \
  --openssl "$OPENSSL3" --expect affected --output before.json
# Upgrade only standalone certifi, leaving pip 26.0.1:
python tests/python-trust-regression.py --chains "$CHAINS" \
  --openssl "$OPENSSL3" --expect clean --pip-expect affected --output certifi-only.json
# Upgrade pip independently, then:
python tests/python-trust-regression.py --chains "$CHAINS" \
  --openssl "$OPENSSL3" --expect clean --live --output after.json
```

The test disables client environment/proxy overrides deliberately to exercise
vendor defaults. Explicit production consumer overrides must be audited
separately. The helper preserves those configuration files and local anchors;
it does not try to override an operator's request-level CA selection.

## Proposed maintenance commands and rollback

Only the operator should run these, after verifying the OS bundle is fixed.
`OWNER`, `VENV`, `BACKUP`, and `SCRIPTS` are explicitly selected service paths,
with a different backup directory for each venv. Stop all three BlitzAPI
services for its maintenance; JoinMarket runtime changes are not needed.

```sh
# Save each venv at its original absolute installation path for rollback.
sudo -u "$OWNER" cp -a "$VENV" "$BACKUP"
sudo -u "$OWNER" "$SCRIPTS/blitz.python-trust.sh" pip "$VENV/bin/python"
# BlitzAPI only; do not install unrelated current-dev requirements:
sudo -u "$OWNER" "$VENV/bin/python" -m pip install --no-deps 'certifi==2026.10.19'
sudo -u "$OWNER" "$SCRIPTS/blitz.python-trust.sh" app "$VENV/bin/python"
```

Run the pip helper separately for the BlitzAPI venv and JoinMarket jmvenv.
Do not install certifi/requests/httpx into JoinMarket just for remediation.
The dependency scope is pip alone in each venv, plus certifi alone in BlitzAPI.
Keep explicit constraints in force; resolve an incompatible pin through its
owner rather than using `--ignore-installed` or removing constraints.

After package checks and targeted service tests, restart BlitzAPI, its Celery
worker, and Celery beat, then verify their loaded versions and TLS behavior.
For rollback, stop affected services, retain the failed venv separately, and
restore the saved directory to the exact original absolute path so existing
entry-point shebangs remain correct. The snapshot contains affected trust:
do not resume unrestricted networking with it. Prefer correcting the failed
package constraint or maintaining an explicitly reviewed system-only client
configuration while rolling forward. Source rollback alone does not undo
installed venv packages.

## Suggested public summaries

RaspiBlitz title: **Fix Python SSL trust after the eMudhra certificate compromise**

Python environments can continue trusting certificates affected by the eMudhra
compromise even after RaspiBlitz's system certificates are updated. This updates
pip's separate certificate bundle, checks BlitzAPI's application bundle before
restarting its services, and covers JoinMarket's installer without changing its
runtime dependencies. Local tests rejected the published compromised chains
and kept valid HTTPS working; deployment and service-restart verification are
still required on the node.

BlitzAPI title: **Stop trusting compromised eMudhra certificates in Python clients**

BlitzAPI's pinned certificate bundle can still trust certificates affected by
the eMudhra compromise even after the node's system certificates are updated.
This updates only certifi in the existing dependency locks so requests and
httpx reject those chains while valid HTTPS continues working. Pip has its own
certificate bundle and needs the separate RaspiBlitz installer update.
