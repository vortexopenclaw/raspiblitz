#!/usr/bin/env python3
"""Isolated command-level TLS regressions; never run installers or sudo.

Run: python3 test/public-download-tls.py
Requires bash, wget, and openssl. Temporary files use TMPDIR when set.
"""
import http.server
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'home.admin/config.scripts'


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'INDEX')

    def log_message(self, format, *args):
        pass


class TLSRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='download-tls-')
        cls.directory = Path(cls.tmp.name)
        cls.cert = cls.directory / 'cert.pem'
        key = cls.directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cls.cert)],
                       check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'https://localhost:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def run_shell(self, code, trusted=False):
        # Intercept only sudo identity switching and prepend bounded wget options.
        # The actual wget executes and performs a real TLS handshake.
        ca = f'--ca-certificate="{self.cert}"' if trusted else ''
        prelude = f'''wget() {{ command wget --no-config --timeout=5 --tries=1 {ca} "$@"; }}
sudo() {{ shift 2; "$@"; }}
torsocks() {{ "$@"; }}
PGPpkeys='{self.url}'
lndUpdatePGPpkeys='{self.url}'
downloadDir='{self.directory}'
'''
        return subprocess.run(['bash', '-c', prelude + code], cwd=self.directory,
                              capture_output=True, text=True)

    def test_key_downloads_fail_closed_and_accept_trusted_control(self):
        for name in ['lnd.install.sh', 'lnd.update.sh', 'bonus.pool.sh', 'bonus.chantools.sh']:
            text = (SCRIPTS / name).read_text()
            command = next(line.strip() for line in text.splitlines()
                           if 'sudo -u admin wget' in line and 'pgp_keys.asc' in line)
            with self.subTest(script=name):
                self.assertNotIn('--no-check-certificate', command)
                result = self.run_shell(command + '\necho CONTINUED')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('CONTINUED', result.stdout)
                self.assertRegex(result.stderr.lower(), 'certificate|issuer')
                result = self.run_shell(command + '\necho CONTINUED', trusted=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('CONTINUED', result.stdout)
                self.assertEqual((self.directory / 'pgp_keys.asc').read_bytes(), b'INDEX')

    def test_packer_download_rejects_invalid_certificate(self):
        text = (ROOT / 'alternative.platforms/amd64/packer/scripts/init.sh').read_text()
        match = re.search(r'^wget .*?authorized_keys[^\n]*', text, re.M | re.S)
        self.assertIsNotNone(match)
        assert match is not None
        command = match.group()
        command = command.replace('https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub', self.url)
        command = command.replace('/home/vagrant/.ssh/authorized_keys', str(self.directory / 'authorized_keys'))
        self.assertNotIn('--no-check-certificate', command)
        result = self.run_shell(command + '\necho CONTINUED')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('CONTINUED', result.stdout)
        self.assertRegex(result.stderr.lower(), 'certificate|issuer')
        self.assertEqual(self.run_shell(command, trusted=True).returncode, 0)

    def test_sphinx_preserves_only_explicit_selfsigned_modes(self):
        text = (SCRIPTS / 'bonus.sphinxrelay.sh').read_text()
        block = text[text.index('  connectionTest="n/a"'):text.index('  # check if already an app')]
        for mode in ['dns&letsencrypt', 'ip2tor&letsencrypt', 'dns&selfsigned',
                     'ip2tor&selfsigned', 'tor', 'localnetwork']:
            for route in ['tor', 'direct']:
                with self.subTest(mode=mode, route=route):
                    code = f"connection='{mode}'\nsphinxrelay_connection='{route}'\npublicURL='{self.url}'\n" + block
                    result = self.run_shell(code)
                    expected = "connectionTest='OK'" if mode.endswith('&selfsigned') else "connectionTest='fail'"
                    self.assertIn(expected, result.stdout)
                    result = self.run_shell(code, trusted=True)
                    self.assertIn("connectionTest='OK'", result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
