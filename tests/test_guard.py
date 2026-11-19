import sys
import unittest
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard

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
        sample = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 [::]:5353 [::]:*'
        rows = guard.parse_ss(sample)
        self.assertEqual(len(rows), 2)
        self.assertTrue(guard.public_binding(rows[0]['local']))
        self.assertTrue(guard.public_binding(rows[1]['local']))
        self.assertFalse(guard.public_binding('127.0.0.1:3000'))
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
