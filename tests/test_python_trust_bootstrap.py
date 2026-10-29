#!/usr/bin/env python3
"""Real isolated pip installs. Requires Python >=3.10 and HTTPS access to PyPI.

Run with Python 3.10 or 3.11 (pip 23.0.1 predates Python 3.12):
python3.11 -m unittest discover -s tests -p 'test_python_trust_bootstrap.py' -v
No services, SSH, or system package writes. Linux system installation still
requires operator acceptance on Debian; the target test uses a temporary path.
"""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'home.admin/config.scripts/blitz.python-trust.sh'


def policy_prefix(source):
    return source[source.index('pip_sudo=('):source.index('done < <(compgen -e)') + len('done < <(compgen -e)')]


def reset_sudo(path, policy, probe=False):
    """Model sudo env_reset, then execute real commands, with no privileges."""
    shim = path / 'sudo-reset.py'
    shim.write_text('import os, subprocess, sys\n' +
                    'args = sys.argv[1:]\nnames = []\n' +
                    "while args and args[0].startswith('-'):\n" +
                    '    option = args.pop(0)\n' +
                    "    if option == '-u': args.pop(0)\n" +
                    "    elif option.startswith('--preserve-env='): names.extend(option.split('=', 1)[1].split(','))\n" +
                    "    elif option != '-H': raise SystemExit('Unexpected sudo option')\n" +
                    'expected = ' + repr(policy) + '\n' +
                    "assert set(names) == set(expected), 'Download policy whitelist differs'\n" +
                    "env = {'PATH': '/usr/bin:/bin', 'HOME': " + repr(str(path)) + '}\n' +
                    'for name in names:\n' +
                    "    assert os.environ[name] == expected[name], 'Download policy value differs'\n" +
                    '    env[name] = os.environ[name]\n' +
                    "assert not any(name in env for name in ('PYTHONPATH', 'PYTHONHOME', 'BASH_ENV', 'UNRELATED_SECRET'))\n" +
                    'sys.exit(subprocess.call(' + ("[\'/usr/bin/true\']" if probe else 'args') + ', env=env))\n')
    return f'{shlex.quote(sys.executable)} -E {shlex.quote(str(shim))}'


class Bootstrap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith('PIP_')}
        cls.env.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1')
        cls.wheels = cls.base / 'wheels'
        cls.wheels.mkdir()
        for version in ('23.0.1', '26.0.1', '26.2.2'):
            cls.run_cmd([sys.executable, '-m', 'pip', 'download', '--no-deps',
                         '--dest', str(cls.wheels), 'pip==' + version])
        cls.ca = cls.base / 'clean.pem'
        cls.bad_ca = cls.base / 'affected.pem'
        for version, dest in (('26.2.2', cls.ca), ('26.0.1', cls.bad_ca)):
            with zipfile.ZipFile(cls.wheels / f'pip-{version}-py3-none-any.whl') as wheel:
                dest.write_bytes(wheel.read('pip/_vendor/certifi/cacert.pem'))
        cls.env.update(PIP_NO_INDEX='1', PIP_FIND_LINKS=str(cls.wheels))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_cmd(cls, args, env=None, ok=True):
        proc = subprocess.run(args, env=env or cls.env, text=True, capture_output=True)
        if ok and proc.returncode:
            raise AssertionError(f'{args}\n{proc.stdout}\n{proc.stderr}')
        return proc

    def venv(self, version):
        path = self.base / self.id().split('.')[-1]
        self.run_cmd([sys.executable, '-m', 'venv', str(path)])
        python = path / 'bin/python'
        self.run_cmd([str(python), '-m', 'pip', 'install', 'pip==' + version])
        return python

    def helper(self, python, ca=None, env=None, mode='pip'):
        return self.run_cmd(['bash', str(HELPER), mode, str(python), str(ca or self.ca)],
                            env=env, ok=False)

    def test_actual_pip23_fresh_venv(self):
        python = self.venv('23.0.1')
        result = self.helper(python)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('26.2.2', self.run_cmd([str(python), '-m', 'pip', '--version']).stdout)

    def test_standalone_helper_trust_gate(self):
        source = (ROOT / 'build_sdcard.sh').read_text()
        gate = source.split("/usr/bin/python3 - <<'PY' || exit 1\n", 1)[1].split('\nPY\n', 1)[0]
        for bundle, accepted in ((self.ca, True), (self.bad_ca, False)):
            code = gate.replace('"/etc/ssl/certs/ca-certificates.crt"', repr(str(bundle)))
            result = self.run_cmd([sys.executable, '-c', code], ok=False)
            self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_actual_modern_pip26(self):
        result = self.helper(self.venv('26.0.1'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_https_bootstrap_pip23(self):
        python = self.venv('23.0.1')
        env = {k: v for k, v in self.env.items() if k not in ('PIP_NO_INDEX', 'PIP_FIND_LINKS')}
        result = self.helper(python, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_https_bootstrap_modern(self):
        python = self.venv('26.0.1')
        env = {k: v for k, v in self.env.items() if k not in ('PIP_NO_INDEX', 'PIP_FIND_LINKS')}
        result = self.helper(python, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_postcondition_rejects_unchanged_affected_pip(self):
        python = self.venv('26.0.1')
        wrapper = python.parent / 'no-op-installer'
        wrapper.write_text('#!/bin/bash\nif [ "$1" = -m ] && [ "$2" = pip ]; then exit 0; fi\nexec '
                           + repr(str(python)) + ' "$@"\n')
        wrapper.chmod(0o755)
        result = self.helper(wrapper)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Affected emSign anchor', result.stderr)

    def test_debian_scheme_selection(self):
        source = HELPER.read_text().split('local_packages=$("$python" - <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
        # Exercise production scheme selection without touching Linux or /usr/local.
        prefix = ('import sys, pathlib; sys.platform="linux"; sys.prefix=sys.base_prefix; '
                  'sys.path.insert(0, f"/usr/local/lib/python{sys.version_info.major}.{sys.version_info.minor}/dist-packages"); '
                  'pathlib.Path.is_file=lambda self: str(self)=="/etc/debian_version";\n')
        result = self.run_cmd([sys.executable, '-c', prefix + source])
        self.assertEqual(result.stdout.strip(), f'/usr/local/lib/python{sys.version_info.major}.{sys.version_info.minor}/dist-packages')
        self.assertNotIn('/usr/local/local/', result.stdout)

    def test_constraint_fails_closed(self):
        python = self.venv('26.0.1')
        constraint = self.base / 'constraints.txt'
        constraint.write_text('pip==26.0.1\n')
        result = self.helper(python, env=dict(self.env, PIP_CONSTRAINT=str(constraint)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('26.0.1', self.run_cmd([str(python), '-m', 'pip', '--version']).stdout)

    def test_outer_update_constraints_stop_restart(self):
        python = self.venv('26.0.1')
        path = python.parent.parent
        source = (ROOT / 'home.admin/config.scripts/blitz.web.api.sh').read_text()
        block = source[source.index('if [ "$1" = "update-code" ]; then'):]
        block = block[:block.index('\n###################')]
        block = block.replace('/home/blitzapi/blitz_api', str(path))
        block = block.replace('ls /etc/systemd/system/blitzapi.service', 'printf blitzapi.service')
        block = block.replace('/home/admin/config.scripts/blitz.python-trust.sh',
                              'bash ' + shlex.quote(str(HELPER)))
        block = block.replace('./venv/bin/python', './venv/bin/python ' + shlex.quote(str(self.ca)))
        block = block.replace('./venv/bin/', shlex.quote(str(python.parent)) + '/')
        constraint = path / 'constraint.txt'
        policy = {k: v for k, v in self.env.items() if k.startswith('PIP_')}
        policy.update(PIP_CONSTRAINT=str(constraint), REQUESTS_CA_BUNDLE=str(self.ca),
                      CURL_CA_BUNDLE=str(self.ca), SSL_CERT_FILE=str(self.ca), SSL_CERT_DIR=str(path))
        runner = reset_sudo(path, policy)
        header = '''
systemctl() { echo "service $*"; }
sudo() {
  if [ "$1" = chown ]; then return 0; fi
  if [ "$3" = git ]; then
    if [ "$4" = rev-parse ]; then
      if [ -f marker ]; then echo new; else touch marker; echo old; fi
    fi
    return 0
  fi
  ''' + runner + ''' "$@"
}
'''
        # Real helper conflict, then successful helper and real requirements conflict.
        for helper_failure in (True, False):
            (path / 'marker').unlink(missing_ok=True)
            constraint.write_text('pip==26.0.1\n' if helper_failure else 'pip==26.2.2\n')
            (path / 'requirements.txt').write_text('pip==26.0.1\n')
            result = subprocess.run(['bash', '-c', header + policy_prefix(source) + '\n' + block,
                                     'test', 'update-code', 'main'],
                                    env=dict(os.environ, **policy, UNRELATED_SECRET='do-not-forward'),
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('ResolutionImpossible', result.stdout + result.stderr)
            self.assertIn('service stop ', result.stdout)
            self.assertNotIn('service start ', result.stdout)
            self.assertEqual('Code changed, updating dependencies' in result.stdout, not helper_failure)

    def test_stale_index_fails_closed(self):
        python = self.venv('23.0.1')
        stale = self.base / 'stale'
        stale.mkdir()
        shutil.copy(self.wheels / 'pip-23.0.1-py3-none-any.whl', stale)
        result = self.helper(python, env=dict(self.env, PIP_FIND_LINKS=str(stale)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('23.0.1', self.run_cmd([str(python), '-m', 'pip', '--version']).stdout)

    def test_affected_bootstrap_refused(self):
        result = self.helper(self.venv('26.0.1'), ca=self.bad_ca)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Affected emSign anchor', result.stderr)
        self.assertNotIn('Successfully installed', result.stdout)

    def test_old_opt_in_truststore_refused(self):
        result = self.helper(self.venv('23.0.1'), env=dict(self.env, PIP_USE_FEATURE='truststore'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('opt-in truststore', result.stderr)

    def test_unsupported_python(self):
        # Run the actual production version guard under a synthetic old version.
        source = HELPER.read_text().split('  "$python" - <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
        result = self.run_cmd([sys.executable, '-c',
                               'import sys; sys.version_info=(3,9,0);\n' + source], ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Python >=3.10', result.stderr)

    def test_system_mode_rejects_venv(self):
        result = self.helper(self.venv('26.0.1'), mode='system-pip')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('system-pip requires Debian system Python', result.stderr)

    def test_target_preserves_existing_pip_and_generates_entrypoints(self):
        python = self.venv('23.0.1')
        target = self.base / 'local/lib/python3/dist-packages'
        # Same installation primitive as production, isolated from /usr/local.
        self.run_cmd([str(python), '-m', 'pip', 'install', '--upgrade', '--target', str(target), 'pip>=26.2.2'])
        self.assertIn('23.0.1', self.run_cmd([str(python), '-m', 'pip', '--version']).stdout)
        self.assertTrue((target / 'bin/pip3').is_file())
        result = self.run_cmd([str(python), '-c', 'import pip; print(pip.__version__)'],
                              env=dict(self.env, PYTHONPATH=str(target)))
        self.assertEqual(result.stdout.strip(), '26.2.2')
        helper = HELPER.read_text()
        self.assertNotIn('--prefix=', helper.split('target=(')[-1])
        self.assertNotIn('--break-system-packages', helper)


class RestartPaths(unittest.TestCase):
    def test_download_policy_at_every_outer_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            policy = {name: 'policy with spaces\nand punctuation=;'
                      for name in ('PIP_CONSTRAINT', 'PIP_BUILD_CONSTRAINT', 'PIP_CERT',
                                   'PIP_FUTURE_SETTING', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                                   'SSL_CERT_FILE', 'SSL_CERT_DIR')}
            runner = reset_sudo(path, policy, probe=True)
            for file, expected in (('build_sdcard.sh', 5),
                                   ('home.admin/config.scripts/blitz.web.api.sh', 8),
                                   ('home.admin/config.scripts/bonus.joinmarket.sh', 2)):
                source = (ROOT / file).read_text()
                # Run every production prefix invocation; command side effects
                # alone are replaced. Sudo's reset strips all non-policy vars.
                lines = [line for line in source.splitlines() if '"${pip_sudo[@]}"' in line]
                self.assertEqual(len(lines), expected)
                self.assertNotRegex(source, r'sudo -(?:u (?:blitzapi|joinmarket)|H) (?:[^\n]*blitz.python-trust|[^\n]* -m pip|\./venv/bin/pip|/home/joinmarket/install.joinmarket)')
                for line in lines:
                    command = line[line.index('"${pip_sudo[@]}"'):].split('; then', 1)[0].split(' ||', 1)[0].split(' >', 1)[0].rstrip('\\; ')
                    header = 'sudo() { ' + runner + ' "$@"; }\n'
                    result = subprocess.run(['bash', '-c', header + policy_prefix(source) + '\n' + command],
                                            env=dict(os.environ, **policy, PYTHONPATH='not-forwarded',
                                                     PYTHONHOME='not-forwarded', UNRELATED_SECRET='not-forwarded'),
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, file + ': ' + result.stdout + result.stderr)
                    self.assertNotIn('policy with spaces', result.stdout + result.stderr)

    def test_update_paths(self):
        # Execute the production update block, replacing external state only.
        source = (ROOT / 'home.admin/config.scripts/blitz.web.api.sh').read_text()
        block = source[source.index('if [ "$1" = "update-code" ]; then'):]
        block = block[:block.index('\n###################')]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            block = block.replace('/home/blitzapi/blitz_api', temp)
            block = block.replace('ls /etc/systemd/system/blitzapi.service', 'printf blitzapi.service')
            header = '''
currentBranch=main
systemctl() { printf 'service %s\\n' "$*"; }
sudo() {
  shift 2
  while [[ "$1" = --preserve-env=* ]]; do shift; done
  if [ "$1" = git ]; then
    case "$2" in
      show-ref) return "$BRANCH_STATUS" ;;
      rev-parse)
        if [ "$CHANGE" = 1 ]; then
          if [ -f "$MARKER" ]; then echo changed; else touch "$MARKER"; echo old; fi
        else echo "$COMMIT"; fi ;;
    esac
  elif [[ "$1" = *blitz.python-trust.sh ]]; then
    echo "check $2"
    if [ "$2" = "$FAIL_CHECK" ]; then return 1; fi
  elif [[ "$1" = *venv/bin/pip ]]; then
    return "$INSTALL_STATUS"
  fi
}
'''
            for branch, failure, change, install_status, starts in (
                    (1, '', 0, 0, False), (0, 'pip', 0, 0, False),
                    (0, 'app', 0, 0, False), (0, '', 0, 0, True),
                    (0, '', 1, 1, False), (0, 'app', 1, 0, False),
                    (0, '', 1, 0, True)):
                marker = path / 'rev-parse-called'
                marker.unlink(missing_ok=True)
                env = dict(os.environ, BRANCH_STATUS=str(branch), FAIL_CHECK=failure,
                           COMMIT='unchanged', INSTALL_STATUS=str(install_status),
                           CHANGE=str(change), MARKER=str(marker))
                result = subprocess.run(['bash', '-c', header + policy_prefix(source) + '\n' + block, 'test', 'update-code', 'main'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual('service start ' in result.stdout, starts, result.stdout + result.stderr)
                if starts:
                    self.assertLess(result.stdout.index('check pip'), result.stdout.index('check app'))
                    self.assertLess(result.stdout.index('check app'), result.stdout.index('service start'))

    def test_image_checkout_and_standalone_fail_closed(self):
        source = (ROOT / 'build_sdcard.sh').read_text()
        block = source[source.index('# Refresh through signed APT'):source.index('"${pip_sudo[@]}" python3 -m pip install grpcio')]
        block = block.replace("/usr/bin/python3 - <<", "python3 - <<")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            helper = root / 'home.admin/config.scripts/blitz.python-trust.sh'
            helper.parent.mkdir(parents=True)
            script = root / 'build.sh'
            header = '''
sudo() {
  while [[ "$1" = --preserve-env=* ]]; do shift; done
  if [ "$1" = -H ]; then
    shift
    while [[ "$1" = --preserve-env=* ]]; do shift; done
    set -- -H "$@"
  fi
  case "$*" in
    'apt-get -o APT::Update::Error-Mode=any update') echo apt-index; return "$INDEX_STATUS" ;;
    'apt-get install --only-upgrade -y ca-certificates') echo apt-ca; return "$APT_STATUS" ;;
    'update-ca-certificates --fresh') echo bundle-refresh; return "$REFRESH_STATUS" ;;
    '-H bash '*) echo helper-invoked; return "$HELPER_STATUS" ;;
    *) echo unexpected-command >&2; return 99 ;;
  esac
}
wget() {
  [[ "$*" = '--no-config --https-only --ca-certificate=/etc/ssl/certs/ca-certificates.crt -O '* ]] || return 99
  echo helper-fetched; return "$FETCH_STATUS"
}
python3() { cat >/dev/null; echo bundle-verified; return "$CA_STATUS"; }
'''
            script.write_text(header + block + '\necho next-download\n')
            for checkout in (True, False):
                if checkout:
                    helper.touch()
                else:
                    helper.unlink(missing_ok=True)
                failures = ('', 'INDEX', 'APT', 'REFRESH', 'CA', 'HELPER')
                if not checkout:
                    failures += ('FETCH',)
                for failure in failures:
                    with self.subTest(checkout=checkout, failure=failure):
                        statuses = {name + '_STATUS': str(int(name == failure))
                                    for name in ('INDEX', 'APT', 'REFRESH', 'CA', 'HELPER', 'FETCH')}
                        result = subprocess.run(['bash', str(script)], text=True, capture_output=True,
                                                env=dict(os.environ, **statuses, TMPDIR=temp))
                        self.assertEqual(result.returncode == 0, not failure, result.stdout + result.stderr)
                        self.assertEqual('next-download' in result.stdout, not failure, result.stdout + result.stderr)
                        if failure in ('INDEX', 'APT', 'REFRESH', 'CA', 'FETCH'):
                            self.assertNotIn('helper-invoked', result.stdout)
                        if failure in ('INDEX', 'APT', 'REFRESH', 'CA'):
                            self.assertNotIn('helper-fetched', result.stdout)
                        if not failure:
                            events = ['apt-index', 'apt-ca', 'bundle-refresh', 'bundle-verified']
                            if not checkout:
                                events.append('helper-fetched')
                            events += ['helper-invoked', 'next-download']
                            self.assertEqual(result.stdout.splitlines(), events)

    def test_vendor_provision_ordering(self):
        source = (ROOT / 'home.admin/_provision.update.sh').read_text()
        comments = '# a conversion of config data or app data is needed'
        python_hook = '/home/admin/config.scripts/blitz.python-trust.sh'
        vendor_hook = '/home/admin/config.scripts/blitz.trust.sh update'
        self.assertLess(source.index(comments), source.index(python_hook))
        self.assertLess(source.index(python_hook), source.index('# if old bitcoin.conf exists'))
        # The same regression exercises the real combined source in the merge
        # worktree, or the companion insertion at its exact upstream anchor.
        if vendor_hook not in source:
            anchor = 'echo "prechecks OK"  >> ${logFile}\n'
            source = source.replace(anchor, anchor + '\n' + vendor_hook + ' >> "${logFile}" 2>&1 || exit 1\n')
        self.assertLess(source.index(vendor_hook), source.index(python_hook))
        block = source[source.index('echo "prechecks OK"'):source.index('# if old bitcoin.conf exists')]
        block = block.replace('/home/admin/config.scripts/blitz.trust.sh', 'vendor')
        block = block.replace(python_hook, 'python_trust')
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / 'log'
            header = '''
vendor() { echo vendor; return "$VENDOR_STATUS"; }
python_trust() { echo python; return "$HELPER_STATUS"; }
'''
            for vendor, helper in ((0, 0), (1, 0), (0, 1)):
                result = subprocess.run(['bash', '-c', header + block + '\necho next-hook'],
                                        env=dict(os.environ, logFile=str(log),
                                                 VENDOR_STATUS=str(vendor), HELPER_STATUS=str(helper)),
                                        text=True, capture_output=True)
                events = log.read_text().splitlines()
                self.assertEqual(events, ['prechecks OK', 'vendor'] + ([] if vendor else ['python']))
                self.assertEqual(result.returncode == 0, not (vendor or helper))
                self.assertEqual('next-hook' in result.stdout, not (vendor or helper))
                log.unlink()

    def test_image_and_upgrade_gate(self):
        image = (ROOT / 'build_sdcard.sh').read_text()
        events = ('sudo apt-get -o APT::Update::Error-Mode=any update || exit 1',
                  'sudo apt-get install --only-upgrade -y ca-certificates || exit 1',
                  'sudo update-ca-certificates --fresh || exit 1',
                  "/usr/bin/python3 - <<'PY' || exit 1", 'trust_helper=',
                  'wget --no-config --https-only --ca-certificate=',
                  '"${pip_sudo[@]}" python3 -m pip install grpcio')
        positions = [image.index(event) for event in events]
        self.assertEqual(positions, sorted(positions))
        # No pip package download is allowed before the bootstrap boundary.
        commands = '\n'.join(line.split('#', 1)[0] for line in image[:positions[0]].splitlines())
        self.assertNotRegex(commands, r'\b(?:pip[23]?\s+install|python[23]?\s+-m\s+pip\s+install)\b')
        self.assertLess(image.index('system-pip /usr/bin/python3'), image.index('pip install grpcio'))
        self.assertIn('system-pip /usr/bin/python3 || exit 1', image)
        update = (ROOT / 'home.admin/_provision.update.sh').read_text()
        self.assertIn('system-pip /usr/bin/python3 >> ${logFile} 2>&1 || exit 1', update)


if __name__ == '__main__':
    unittest.main()
