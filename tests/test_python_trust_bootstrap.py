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
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'home.admin/config.scripts/blitz.python-trust.sh'


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
                result = subprocess.run(['bash', '-c', header + block, 'test', 'update-code', 'main'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual('service start ' in result.stdout, starts, result.stdout + result.stderr)
                if starts:
                    self.assertLess(result.stdout.index('check pip'), result.stdout.index('check app'))
                    self.assertLess(result.stdout.index('check app'), result.stdout.index('service start'))

    def test_image_checkout_and_standalone_fail_closed(self):
        source = (ROOT / 'build_sdcard.sh').read_text()
        block = source[source.index('trust_helper='):source.index('sudo -H python3 -m pip install grpcio')]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            helper = root / 'home.admin/config.scripts/blitz.python-trust.sh'
            helper.parent.mkdir(parents=True)
            script = root / 'build.sh'
            header = '''
sudo() { echo helper-invoked; return "$HELPER_STATUS"; }
wget() { echo helper-fetched; return "$FETCH_STATUS"; }
'''
            script.write_text(header + block + '\necho next-download\n')
            for checkout, helper_status, fetch_status, expected in (
                    (True, 0, 0, True), (True, 1, 0, False),
                    (False, 0, 0, True), (False, 1, 0, False), (False, 0, 1, False)):
                if checkout:
                    helper.touch()
                else:
                    helper.unlink(missing_ok=True)
                result = subprocess.run(['bash', str(script)], text=True, capture_output=True,
                                        env=dict(os.environ, HELPER_STATUS=str(helper_status),
                                                 FETCH_STATUS=str(fetch_status), TMPDIR=temp))
                self.assertEqual('next-download' in result.stdout, expected, result.stdout + result.stderr)
                if not checkout and fetch_status:
                    self.assertNotIn('helper-invoked', result.stdout)

    def test_image_and_upgrade_gate(self):
        image = (ROOT / 'build_sdcard.sh').read_text()
        self.assertLess(image.index('system-pip /usr/bin/python3'), image.index('pip install grpcio'))
        self.assertIn('system-pip /usr/bin/python3 || exit 1', image)
        update = (ROOT / 'home.admin/_provision.update.sh').read_text()
        self.assertIn('system-pip /usr/bin/python3 >> ${logFile} 2>&1 || exit 1', update)


if __name__ == '__main__':
    unittest.main()
