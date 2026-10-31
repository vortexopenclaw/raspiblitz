#!/usr/bin/python3
"""Run ONLY in the disposable container: writes /usr/bin and dpkg database."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path('/work')
SCRIPT = ROOT / 'home.admin/config.scripts/tor.install.sh'
FIXTURE = Path('/fixture')
CASES = Path('/cases')
TRACE_LINES = set()


def command(args, **kw):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, **kw)
    if p.returncode:
        raise RuntimeError(f'{args}: {p.stdout}')
    return p.stdout


def package(version):
    directory = FIXTURE / ('build-' + version)
    (directory / 'DEBIAN').mkdir(parents=True)
    (directory / 'usr/bin').mkdir(parents=True)
    (directory / 'DEBIAN/control').write_text(
        f'Package: tor\nVersion: {version}\nArchitecture: all\n'
        'Maintainer: Test <test@example.invalid>\nDescription: Inert Tor fixture\n')
    binary = directory / 'usr/bin/tor'
    binary.write_text('#!/bin/sh\n[ "$1" = --version ] || exit 99\n'
                      '[ "${FAULT:-}" != empty-version ] || { touch "$CASE/reached"; exit 0; }\n'
                      f'echo "Tor version {version}."\n'
                      '[ "${FAULT:-}" != version-error ] || { touch "$CASE/reached"; exit 1; }\n')
    binary.chmod(0o755)
    target = FIXTURE / f'tor_{version}_all.deb'
    command(['dpkg-deb', '--build', str(directory), str(target)])


def setup_module():
    assert Path('/.dockerenv').exists(), 'Do not run on a host'
    assert os.geteuid() == 0
    FIXTURE.mkdir()
    CASES.mkdir()
    home = FIXTURE / 'gnupg'
    home.mkdir(mode=0o700)
    os.environ['GNUPGHOME'] = str(home)
    command(['gpg', '--batch', '--passphrase', '', '--quick-generate-key',
             'Isolated fixture <test@example.invalid>', 'rsa2048', 'sign', '0'])
    info = command(['gpg', '--with-colons', '--list-keys'])
    fingerprint = next(x.split(':')[9] for x in info.splitlines() if x.startswith('fpr:'))
    (FIXTURE / 'fingerprint').write_text(fingerprint)
    (FIXTURE / 'key.asc').write_text(command(['gpg', '--armor', '--export', fingerprint]))
    (FIXTURE / 'key.gpg').write_bytes(subprocess.check_output(['gpg', '--export', fingerprint]))
    command(['gpg', '--batch', '--passphrase', '', '--quick-generate-key',
             'Untrusted extra key <extra@example.invalid>', 'ed25519', 'sign', '0'])
    (FIXTURE / 'bundle.asc').write_text(command(['gpg', '--armor', '--export']))
    for version in ('0.4.8.1', '0.4.9.1', '0.4.9.2'):
        package(version)
    Path('/home/admin/download').mkdir(parents=True)
    Path('/usr/bin/snowflake-client').touch()
    Path('/usr/bin/snowflake-proxy').touch()
    bindir = FIXTURE / 'bin'
    bindir.mkdir()
    for name in ('sudo', 'lsb_release', 'curl', 'gpg', 'dpkg', 'dpkg-query',
                 'apt', 'debuild', 'systemctl', 'setcap', 'mktemp', 'install', 'tee'):
        (bindir / name).symlink_to(ROOT / 'tests/tor-update/shim.py')
    (ROOT / 'tests/tor-update/shim.py').chmod(0o755)
    Path('/etc/apt/sources.list.d').mkdir(exist_ok=True)
    (FIXTURE / 'bash-env').write_text("PS4='+${BASH_SOURCE}:${LINENO}: '\n")
    print('production_sha256=' + hashlib.sha256(SCRIPT.read_bytes()).hexdigest(), flush=True)


class Update(unittest.TestCase):
    def run_case(self, fault='', source=False, arch='arm64', unit='tor@default', old='0.4.8.1', action='update'):
        case = CASES / self.id().split('.')[-1]
        case.mkdir()
        repo = case / 'repo'
        repo.mkdir()
        for version in (('0.4.8.1', '0.4.9.1', '0.4.9.2') if old == '0.4.9.2' else ('0.4.8.1', '0.4.9.1')):
            shutil.copy(FIXTURE / f'tor_{version}_all.deb', repo)
        # dpkg-scanpackages reports warnings on stderr; only package records belong in Packages.
        packages = subprocess.check_output(['dpkg-scanpackages', '--multiversion', '.', '/dev/null'],
                                           cwd=repo, stderr=subprocess.DEVNULL).decode()
        (repo / 'Packages').write_text(packages)
        (repo / 'Release').write_text(command(['apt-ftparchive', 'release', '.'], cwd=repo))
        command(['gpg', '--batch', '--yes', '--local-user', (FIXTURE / 'fingerprint').read_text(), '--clearsign', '--output', str(repo / 'InRelease'), str(repo / 'Release')])
        (case / 'lists/partial').mkdir(parents=True)
        (case / 'archives/partial').mkdir(parents=True)
        (case / 'sources.list').write_text(f'deb [signed-by=/fixture/key.gpg] file:{repo} ./\n')
        (case / 'apt.conf').write_text(
            f'Dir::Etc::sourcelist "{case}/sources.list";\n'
            'Dir::Etc::sourceparts "-";\n'
            f'Dir::State::lists "{case}/lists";\n'
            f'Dir::Cache::archives "{case}/archives";\n'
            'APT::Get::List-Cleanup "0";\n')
        env = dict(os.environ, APT_CONFIG=str(case / 'apt.conf'), CASE=str(case),
                   FAULT=fault, ARCH=arch, UNIT=unit,
                   PATH=str(FIXTURE / 'bin') + ':' + os.environ['PATH'])
        command(['/usr/bin/dpkg', '-i', str(FIXTURE / f'tor_{old}_all.deb')])
        command(['/usr/bin/apt-get', 'update'],
                env=dict(env, PATH='/usr/sbin:/usr/bin:/sbin:/bin'))
        (case / 'service').write_text('running')
        Path('/usr/share/keyrings/torproject.gpg').write_text('previous-keyring')
        with (case / 'trace').open('w') as trace:
            env.update(BASH_XTRACEFD=str(trace.fileno()), BASH_ENV='/fixture/bash-env')
            p = subprocess.run(['bash', '-x', str(SCRIPT), action] + (['source'] if source else []),
                               env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               pass_fds=(trace.fileno(),))
        (case / 'output').write_text(p.stdout)
        for line in (case / 'trace').read_text().splitlines():
            try:
                if line.lstrip('+').startswith(str(SCRIPT) + ':'):
                    TRACE_LINES.add(int(line.lstrip('+').split(':')[1]))
            except ValueError:
                pass
        events = [json.loads(x) for x in (case / 'events').read_text().splitlines()]
        version = command(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'tor']).strip()
        expected = 0 if not fault or fault == 'key-retry' else 1
        self.assertEqual(p.returncode, expected, p.stdout)
        if fault:
            self.assertTrue((case / 'reached').exists(), 'fault not reached: ' + p.stdout)
        if expected == 0:
            self.assertEqual(version, '0.4.9.1' if old != '0.4.9.2' else old)
            self.assertEqual((case / 'service').read_text(), 'stopped' if action == 'install' else 'running')
            if not source:
                sources = Path('/etc/apt/sources.list.d/tor.list').read_text()
                self.assertIn(f'arch={arch} signed-by=/usr/share/keyrings/torproject.gpg', sources)
        elif action == 'install':
            self.assertIn('! FAIL:', p.stdout)
        elif fault != 'rollback-failure':
            self.assertEqual(version, old, p.stdout)
            # Compare actual packaged executable bytes, not only the database.
            self.assertEqual(Path('/usr/bin/tor').read_bytes(),
                             (FIXTURE / f'build-{old}/usr/bin/tor').read_bytes())
            if fault != 'restart-permanent':
                self.assertEqual((case / 'service').read_text(), 'running')
        if fault == 'checksum':
            self.assertIn('Hash Sum mismatch', p.stdout)
        if fault == 'signature':
            self.assertIn('BADSIG', p.stdout)
        if fault == 'rollback-failure':
            self.assertIn('Package rollback failed', p.stdout)
            self.assertEqual(version, '0.4.9.1')
        if fault == 'restart-permanent':
            self.assertIn('Unable to restart the previous Tor service', p.stdout)
            self.assertEqual((case / 'service').read_text(), 'stopped')
        stages = re.findall(r'Recovery files retained in (\S+)', p.stdout)
        for stage in stages:
            directory = Path(stage)
            self.assertEqual(directory.stat().st_uid, 0)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            if fault != 'backup-download':
                self.assertEqual((directory / 'previous.deb').read_bytes(),
                                 (FIXTURE / f'tor_{old}_all.deb').read_bytes())
        for event in events:
            if event[:2] == ['systemctl', 'stop'] or event[:2] == ['systemctl', 'restart']:
                self.assertEqual(event[2], unit)
        if fault.startswith('key-') and fault != 'key-retry':
            self.assertEqual(Path('/usr/share/keyrings/torproject.gpg').read_text(), 'previous-keyring')
            self.assertEqual(sum(e[:2] == ['curl', '-fsS'] for e in events), 0 if fault == 'key-stage' else 2)
        return case, events

    def test_install_success(self):
        self.run_case(action='install')

    def test_install_empty_version(self):
        self.run_case('empty-version', action='install')

    def test_install_old_version(self):
        self.run_case('old-version', action='install')

    def test_verified_amd64(self):
        self.run_case(arch='amd64')

    def test_verified_arm64(self):
        self.run_case()

    def test_legacy_unit(self):
        self.run_case(unit='tor')

    def test_existing_version_noop(self):
        self.run_case(old='0.4.9.1')

    def test_newer_version_no_downgrade(self):
        self.run_case(old='0.4.9.2')

    def test_retry_clearnet(self):
        case, events = self.run_case('key-retry')
        curls = [e for e in events if e[0] == 'curl']
        self.assertEqual(len(curls), 2)
        self.assertIn('-x', curls[0])
        self.assertNotIn('-x', curls[1])
        self.assertTrue(any('https://deb.torproject.org/' in x for x in curls[1]))

    def test_source_stop_legacy(self):
        self.run_case('stop', source=True, unit='tor')

    def test_source_missing_download_dir(self):
        shutil.rmtree('/home/admin/download')
        self.run_case(source=True)

    def test_source_success(self):
        self.run_case(source=True)

    def test_source_legacy(self):
        self.run_case(source=True, unit='tor')


def add_case(name, fault, source=False):
    def test(self):
        self.run_case(fault, source=source)
    setattr(Update, 'test_' + name, test)


for fault in ('key-download', 'key-fingerprint', 'key-dearmor', 'signature', 'checksum',
              'download', 'transport-download', 'transport-install', 'apt-install',
              'restart', 'restart-permanent', 'rollback-failure', 'missing-package',
              'backup-download', 'empty-version', 'old-version', 'version-error', 'signal', 'update-stage', 'key-stage',
              'keyring-install', 'key-inspect', 'bundled-key', 'sources-write'):
    add_case('apt_' + fault.replace('-', '_'), fault)
for fault in ('source-download', 'build-tools', 'build-dep', 'build', 'missing-build',
              'stop', 'source-install', 'restart', 'empty-version', 'old-version', 'version-error', 'signature',
              'source-stage', 'source-layout', 'multiple-build'):
    add_case('source_' + fault.replace('-', '_'), fault, True)


def verify_command_sites():
    """Audit command/condition sites in the changed helpers/update block.

    This is a Bash xtrace site gate, not a claim of shell branch coverage.
    Multiline expansions are attributed to their final expansion line by Bash.
    """
    lines = SCRIPT.read_text().splitlines()
    spans = []
    for start, end in (('add_tor_sources(){', 'configure_default_torrc(){'),
                       ('require_supported_tor_version(){', 'action=$1'),
                       ('if [ "${action}" = "update" ]; then', '# if above')):
        first = next(i for i, line in enumerate(lines) if line.startswith(start))
        last = next(i for i, line in enumerate(lines[first + 1:], first + 1) if line.startswith(end))
        spans.extend(range(first, last))
    pattern = re.compile(r'^(local |[a-z_]+=|for |if |curl |gpg |sudo |rm |echo |return |trap |exit |case |cd |apt |debuild |mkdir |set -- tor_|\[ )')
    required = set()
    for i in spans:
        line = lines[i].strip()
        if not pattern.match(line):
            continue
        if line.startswith('fingerprint=$('):
            i = next(j for j in range(i + 1, len(lines)) if lines[j].strip().endswith("')"))
        elif line.startswith('echo "deb '):
            i += 1
        required.add(i + 1)
    missing = sorted(required - TRACE_LINES)
    print(f'Changed-path command/condition sites traced: {len(required - set(missing))}/{len(required)}')
    if missing:
        print('Untraced sites: ' + repr([(i, lines[i - 1]) for i in missing]))
    return not missing


if __name__ == '__main__':
    setup_module()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Update))
    Path('/work/trace-lines.json').write_text(json.dumps(sorted(TRACE_LINES)))
    print(f'Traced production lines: {len(TRACE_LINES)}; see trace-lines.json')
    print('TRACE_LINES=' + json.dumps(sorted(TRACE_LINES)))
    covered = verify_command_sites()
    raise SystemExit(0 if result.wasSuccessful() and covered else 1)
