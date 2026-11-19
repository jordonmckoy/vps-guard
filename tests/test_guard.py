import json
import sys
import unittest
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard

class StubHost(guard.Host):
    """Returns canned command output by probe name instead of running commands."""

    def __init__(self, outputs):
        super().__init__()
        self.outputs = outputs

    def run(self, name, args, timeout=12):
        out = self.outputs.get(name)
        return {'ok': out is not None, 'out': out or '', 'err': '' if out is not None else 'stubbed failure'}

class Tests(unittest.TestCase):
    def test_provider_selection(self):
        self.assertEqual(guard.choose_provider(lambda _: '2', lambda _: None), 'digitalocean')
        self.assertEqual(guard.choose_provider(lambda _: '1', lambda _: None), 'hetzner')
        self.assertEqual(guard.choose_provider(lambda _: '3', lambda _: None), 'other')

    def test_provider_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.vps-guard.json'
            self.assertIsNone(guard.load_provider(path))
            guard.save_provider('digitalocean', path)
            self.assertEqual(guard.load_provider(path), 'digitalocean')
            with self.assertRaises(SystemExit):
                guard.save_provider('hetzner', path)

    def test_provider_advice(self):
        self.assertIn('DigitalOcean', guard.provider_advice('digitalocean'))
        self.assertIn('Hetzner', guard.provider_advice('hetzner'))

    def test_ss(self):
        sample = ('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                  'udp UNCONN 0 0 [::]:5353 [::]:*\n'
                  'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
                  'tcp LISTEN 0 128 100.101.102.103:5432 0.0.0.0:*\n'
                  'tcp LISTEN 0 128 8.8.8.8:6379 0.0.0.0:*')
        rows = guard.parse_ss(sample)
        self.assertEqual([row['scope'] for row in rows], ['wildcard', 'wildcard', 'loopback', 'tailscale', 'public'])
        self.assertEqual(rows[0]['process'], 'sshd')
        self.assertEqual(rows[4]['port'], '6379')

    def test_address_scope(self):
        self.assertEqual(guard.address_scope('fd7a:115c:a1e0::1'), 'tailscale')
        self.assertEqual(guard.address_scope('10.0.0.5'), 'private')
        self.assertEqual(guard.address_scope(''), 'wildcard')

    def test_ufw_restricts_ssh(self):
        header = 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n'
        self.assertTrue(guard.ufw_restricts_ssh(header + '22/tcp on tailscale0  ALLOW IN  Anywhere', '22'))
        self.assertFalse(guard.ufw_restricts_ssh(header + '22/tcp  ALLOW IN  Anywhere', '22'))
        self.assertFalse(guard.ufw_restricts_ssh(header + 'OpenSSH  ALLOW IN  Anywhere', '22'))
        self.assertTrue(guard.ufw_restricts_ssh(header + '2222/tcp  ALLOW IN  Anywhere', '22'))
        self.assertFalse(guard.ufw_restricts_ssh('Status: inactive', '22'))

    def test_ssh_exposure(self):
        listeners = guard.parse_ss('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*')
        public_ufw = 'Status: active\nDefault: deny (incoming)\n22/tcp  ALLOW IN  Anywhere'
        status = lambda *args: next(guard.check_ssh_exposure(*args))['status']
        self.assertEqual(status(listeners, {'port': '22'}, public_ufw, True), 'fail')
        self.assertEqual(status(listeners, {'port': '22'}, public_ufw, False), 'review')
        self.assertEqual(status(listeners, {'port': '22'}, None, True), 'review')
        self.assertEqual(status(listeners, {'port': '2222'}, public_ufw, True), 'pass')
        self.assertEqual(status(None, None, None, True), 'unknown')

    def test_go_time(self):
        parsed = guard.parse_go_time('2027-05-17T12:00:00.123456789Z')
        self.assertEqual(parsed, guard.dt.datetime(2027, 5, 17, 12, tzinfo=guard.dt.timezone.utc))

    def test_key_label(self):
        self.assertEqual(guard.key_label('ssh-ed25519 AAAAC3Nza me@laptop'), 'ssh-ed25519 me@laptop')
        self.assertEqual(guard.key_label('from="10.0.0.1" ssh-rsa AAAAB3 deploy'), 'ssh-rsa deploy')

    def test_tailscale(self):
        host = StubHost({
            'tailscaled_enabled': 'enabled',
            'tailscale_prefs': json.dumps({'RunSSH': True, 'AdvertiseRoutes': ['0.0.0.0/0'], 'AutoUpdate': {'Apply': False}}),
            'tailscale_serve': json.dumps({'AllowFunnel': {'vps.example.ts.net:443': True}}),
        })
        status = {'BackendState': 'Running', 'Self': {'KeyExpiry': '2026-01-01T00:00:00Z'}, 'Health': ['dns broken']}
        results = {f['id']: f['status'] for f in guard.check_tailscale(host, status, {'ipv4': '1', 'ipv6': '0'})}
        self.assertEqual(results['tailscale_key_expiry'], 'fail')
        self.assertEqual(results['tailscale_tags'], 'review')
        self.assertEqual(results['tailscale_boot'], 'pass')
        self.assertEqual(results['tailscale_health'], 'review')
        self.assertEqual(results['tailscale_updates'], 'review')
        self.assertEqual(results['tailscale_routes'], 'review')
        self.assertEqual(results['tailscale_ssh'], 'review')
        self.assertEqual(results['tailscale_funnel'], 'review')
        self.assertEqual([f['id'] for f in guard.check_tailscale(host, None, {})], ['tailscale'])

    def test_docker(self):
        container = {'Name': '/db', 'HostConfig': {'Privileged': True, 'NetworkMode': 'bridge'},
                     'NetworkSettings': {'Ports': {'5432/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '5432'}],
                                                   '8080/tcp': [{'HostIp': '100.64.0.1', 'HostPort': '8080'}],
                                                   '9000/tcp': None}},
                     'Mounts': [{'Source': '/var/run/docker.sock'}]}
        host = StubHost({'docker': 'abc123', 'docker_inspect': json.dumps([container])})
        results = {f['id']: f for f in guard.check_docker(host)}
        self.assertEqual(results['docker_publish']['evidence'], {'db': ['0.0.0.0:5432->5432/tcp']})
        self.assertEqual(results['docker_isolation']['evidence'], {'db': ['privileged', 'docker socket mounted']})

    def test_ssh(self):
        self.assertEqual(guard.ssh_values('permitrootlogin no\npasswordauthentication yes'),
                         {'permitrootlogin': 'no', 'passwordauthentication': 'yes'})
    def test_plan(self):
        report = {'findings': [guard.finding('auto_updates', 'medium', 'review', 't', {}, 'r', 'enable-unattended-upgrades')]}
        self.assertEqual(guard.propose(report)[0]['id'], 'enable-unattended-upgrades')
    def test_no_unconfirmed_changes(self):
        with self.assertRaises(SystemExit):
            guard.apply_fix('enable-unattended-upgrades', False)

if __name__ == '__main__':
    unittest.main()
