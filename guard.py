#!/usr/bin/env python3
"""VPS Guard: conservative, provider-agnostic local VPS security audit."""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

VERSION = '0.2.0'
PROVIDERS = ('hetzner', 'digitalocean', 'other')
CONFIG_NAME = '.vps-guard.json'

def choose_provider(input_fn=input, output_fn=print):
    output_fn('Which VPS provider do you use?')
    output_fn('  1) Hetzner\n  2) DigitalOcean\n  3) Other')
    mapping = {'1': 'hetzner', '2': 'digitalocean', '3': 'other',
               'hetzner': 'hetzner', 'digitalocean': 'digitalocean', 'other': 'other'}
    while True:
        try:
            choice = input_fn('Select [1-3]: ').strip().lower()
        except (EOFError, KeyboardInterrupt) as exc:
            raise SystemExit('Provider selection cancelled; no configuration written.') from exc
        if choice in mapping:
            return mapping[choice]
        output_fn('Enter 1, 2 or 3.')

def save_provider(provider, path):
    if provider not in PROVIDERS:
        raise ValueError('Unsupported provider')
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise SystemExit(f'Config already exists or is a symlink: {path}; edit it manually to change provider.')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'provider': provider}, stream, indent=2)
        stream.write('\n')

def load_provider(path):
    path = Path(path)
    if not path.is_file():
        return None
    try:
        provider = json.loads(path.read_text())['provider']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f'Invalid provider configuration: {exc}') from exc
    if provider not in PROVIDERS:
        raise SystemExit('Unknown provider in configuration file')
    return provider

def provider_advice(provider):
    console = {'hetzner': 'Hetzner Cloud Console',
               'digitalocean': 'DigitalOcean Control Panel',
               'other': 'your hosting provider control panel'}[provider]
    return (f'Check {console}: verify cloud firewall rules (default-deny inbound where supported), '
            'backups, snapshots, recovery access and account MFA. '
            'This local scan does not verify provider account settings.')


def run(args, timeout=12):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {'ok': p.returncode == 0, 'out': p.stdout.strip(), 'err': p.stderr.strip(), 'code': p.returncode}
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as ex:
        return {'ok': False, 'out': '', 'err': str(ex), 'code': None}

def finding(id, severity, status, title, evidence, recommendation, fix=None):
    return dict(id=id, severity=severity, status=status, title=title,
                evidence=evidence, recommendation=recommendation, fix=fix)

def ssh_values(text):
    result = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip().lower()
    return result

def parse_ss(text):
    """Extract listening protocol and local endpoint from ss -H -lntu output."""
    entries = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) >= 5:
            proto = cols[0].lower()
            local = cols[4]
            if proto in ('tcp', 'udp'):
                entries.append({'protocol': proto, 'local': local})
    return entries

def public_binding(endpoint):
    # ss endpoints include 0.0.0.0:22, [::]:22, *:22
    host = endpoint.rsplit(':', 1)[0].strip('[]')
    return host in ('0.0.0.0', '::', '*')

def audit(provider="other"):
    findings = []
    info = {'hostname': socket.gethostname(), 'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'version': VERSION, 'provider': provider, 'root': os.geteuid() == 0, 'checks': {}}
    def capture(name, args, timeout=12):
        r = run(args, timeout)
        info['checks'][name] = {'ok': r['ok'], 'error': r['err'][:250] if not r['ok'] else ''}
        return r

    osr = Path('/etc/os-release')
    info['os'] = osr.read_text(errors='replace')[:2000] if osr.exists() else 'unknown'
    info['kernel'] = capture('kernel', ['uname', '-r'])['out']
    ss = capture('listeners', ['ss', '-H', '-lntu'])
    if ss['ok']:
        entries = parse_ss(ss['out'])
        info['listening'] = entries
        exposed = [e for e in entries if public_binding(e['local'])]
        risky = [e for e in exposed if re.search(r':(2375|2376|3306|5432|6379|9200|27017|9090|3000)$', e['local'])]
        findings.append(finding('listeners', 'high' if risky else 'info', 'fail' if risky else 'review',
            'Listening services on wildcard interfaces', {'wildcard': exposed},
            'Review each wildcard listener, especially database, Docker API and metrics ports. Validate actual internet reachability from outside the server.'))
    else:
        findings.append(finding('listeners', 'medium', 'unknown', 'Cannot enumerate listening ports', ss['err'], 'Install iproute2 or run with adequate privileges.'))

    sshd = shutil.which('sshd') or '/usr/sbin/sshd'
    ssh = capture('ssh_effective', [sshd, '-T'])
    if ssh['ok']:
        conf = ssh_values(ssh['out'])
        for key, safe, label, risk in [
            ('permitrootlogin', {'no'}, 'Root SSH login', 'high'),
            ('passwordauthentication', {'no'}, 'SSH password authentication', 'high'),
            ('kbdinteractiveauthentication', {'no'}, 'SSH keyboard-interactive authentication', 'high'),
            ('permitemptypasswords', {'no'}, 'Empty SSH passwords', 'critical'),
            ('x11forwarding', {'no'}, 'SSH X11 forwarding', 'low'),
        ]:
            value = conf.get(key, 'unknown')
            findings.append(finding('ssh_' + key, risk, 'pass' if value in safe else 'fail' if value != 'unknown' else 'unknown',
                label, {'effective_value': value}, 'Review SSH config and access requirements before applying changes.'))
    else:
        findings.append(finding('ssh', 'medium', 'unknown', 'Cannot inspect effective SSH config', ssh['err'],
            'If OpenSSH server is installed, run with permission to inspect sshd -T; confirm whether SSH is actually in use.'))

    ufw = capture('ufw', ['ufw', 'status', 'verbose'])
    if ufw['ok']:
        active = 'status: active' in ufw['out'].lower()
        findings.append(finding('ufw', 'medium', 'pass' if active else 'review', 'UFW host firewall',
            {'active': active, 'summary': ufw['out'][:3000]},
            'Use a correctly scoped host firewall and provider firewall where available. Check Docker published ports independently.'))
    else:
        findings.append(finding('ufw', 'info', 'unknown', 'UFW unavailable or inaccessible', ufw['err'],
            'A different firewall such as nftables may be in use; inspect provider and host rules.'))

    updates = capture('updates', ['apt-get', '-s', 'upgrade'], 30) if shutil.which('apt-get') else {'ok': False, 'err': 'Not Debian/Ubuntu or apt-get missing', 'out': ''}
    if updates['ok']:
        up = [x for x in updates['out'].splitlines() if x.startswith('Inst ')]
        info['pending_updates'] = len(up)
        findings.append(finding('updates', 'medium', 'fail' if up else 'pass', 'APT upgrade candidates',
            {'count': len(up), 'packages': [x.split()[1] for x in up[:35]]},
            'Review package updates; apt simulation may rely on stale lists. Do not auto-upgrade production workloads without a maintenance plan.'))
    else:
        findings.append(finding('updates', 'info', 'unknown', 'Could not simulate APT upgrades', updates.get('err', ''),
            'Inspect package manager security updates manually.'))

    svc = capture('unattended', ['systemctl', 'is-enabled', 'unattended-upgrades.service'])
    timer = capture('apt_timer', ['systemctl', 'is-enabled', 'apt-daily-upgrade.timer'])
    conf = Path('/etc/apt/apt.conf.d/20auto-upgrades')
    conftext = conf.read_text(errors='replace') if conf.is_file() else ''
    enabled = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', conftext))
    findings.append(finding('auto_updates', 'medium', 'pass' if enabled else 'review', 'Unattended upgrades configuration',
        {'periodic_config_enabled': enabled, 'service_enabled': svc['out'], 'timer_enabled': timer['out']},
        'Verify unattended-upgrades is installed and configured with the desired security origins and reboot policy.', 'enable-unattended-upgrades'))

    docker = capture('docker', ['docker', 'ps', '--format', '{{json .}}'])
    if docker['ok']:
        containers = []
        for line in docker['out'].splitlines():
            try:
                item = json.loads(line)
                containers.append({k: item.get(k) for k in ('Names', 'Image', 'Ports', 'Status')})
            except json.JSONDecodeError:
                pass
        info['docker_containers'] = containers
        published = [x for x in containers if re.search(r'(0\.0\.0\.0:|\[::\]:|:::)', x.get('Ports') or '')]
        findings.append(finding('docker_publish', 'high', 'fail' if published else 'pass',
            'Docker containers with wildcard published host ports', {'published': published},
            'Publish only public reverse proxy ports; restrict internal services to private Docker networks or 127.0.0.1.'))
    else:
        findings.append(finding('docker', 'info', 'unknown', 'Docker inspection unavailable',
            docker['err'] or 'Docker not installed or daemon inaccessible',
            'If Docker is in use, rerun with permissions to query the Docker daemon.'))

    tailscale = capture('tailscale', ['tailscale', 'status', '--json'])
    if tailscale['ok']:
        try:
            ts = json.loads(tailscale['out'])
            state = ts.get('BackendState', 'unknown')
        except ValueError:
            state = 'unknown'
        findings.append(finding('tailscale', 'info', 'pass' if state == 'Running' else 'review',
            'Tailscale administrative network', {'backend_state': state},
            'Prefer private admin access; verify ACLs, recovery and connectivity before disabling public SSH.'))
    else:
        findings.append(finding('tailscale', 'info', 'review', 'Tailscale not confirmed',
            'Not installed, stopped or inaccessible', 'Consider Tailscale for management access if appropriate.'))

    root = capture('root_uid', ['id', '-u'])
    findings.append(finding('privilege', 'info', 'review', 'Audit execution privileges', {'euid': os.geteuid()},
        'Running with sudo improves visibility but reports can contain sensitive infrastructure metadata.'))
    findings.append(finding('provider_controls', 'high', 'unknown', 'Provider firewall and backups',
        {'provider': provider, 'checked_via_api': False}, provider_advice(provider)))
    return {'metadata': info, 'findings': findings}

def summary(report):
    counts = {}
    for f in report['findings']:
        counts[f['status']] = counts.get(f['status'], 0) + 1
    return counts

def markdown(report):
    m = report['metadata']; counts = summary(report)
    out = [f'# VPS Guard audit — {m["hostname"]}', '',
           f'UTC: {m["timestamp_utc"]}', f'Version: {m["version"]}', f'Provider: {m["provider"]}',
           f'Counts: {json.dumps(counts, sort_keys=True)}', '',
           '> This is a configuration audit, not proof of external network reachability or absence of compromise.', '',
           '| Severity | Status | Check |', '|---|---|---|']
    for f in report['findings']:
        out.append(f'| {f["severity"]} | {f["status"]} | {f["id"]} |')
    out.extend(['', '## Findings', ''])
    for f in report['findings']:
        out.extend([f'### {f["title"]} ({f["id"]})', '',
                    f'**{f["severity"].upper()} / {f["status"].upper()}**', '',
                    '**Evidence**', '', '```json', json.dumps(f['evidence'], indent=2), '```', '',
                    '**Recommendation:** ' + f['recommendation'], ''])
    out.extend(['## Limitations', '',
                '- This tool does not test external reachability, provider account security, image CVEs or application logic.',
                '- `ss` wildcard bindings are not proof that a port is publicly reachable.',
                '- An `unknown` result means the check was not completed; it is not a pass.',
                '- Do not publish reports without reviewing hostnames, service names, ports and package information.'])
    return '\n'.join(out) + '\n'

def propose(report):
    plan = []
    if any(f['id'] == 'auto_updates' and f['status'] != 'pass' for f in report['findings']):
        plan.append({'id': 'enable-unattended-upgrades', 'risk': 'medium',
                     'effect': 'Install unattended-upgrades and enable its APT periodic configuration',
                     'requires': 'Debian/Ubuntu with apt-get; maintenance approval',
                     'rollback': 'Restore backed-up APT configuration file, then review installed package state'})
    return plan

def apply_fix(name, confirm):
    if name != 'enable-unattended-upgrades':
        raise SystemExit('Unknown or unsupported fix. No action taken.')
    if not confirm:
        raise SystemExit('Dry run only. To execute, pass --confirm after reading the README and plan.')
    if os.geteuid() != 0:
        raise SystemExit('Root/sudo required. No action taken.')
    if not shutil.which('apt-get'):
        raise SystemExit('apt-get unavailable. No action taken.')
    target = Path('/etc/apt/apt.conf.d/20auto-upgrades')
    if target.is_symlink():
        raise SystemExit('Refusing to replace symlinked APT configuration.')
    if target.exists():
        raise SystemExit('Existing 20auto-upgrades configuration detected. Refusing to overwrite; review manually.')
    print('Installing unattended-upgrades; no firewall/SSH/network changes will be made.', flush=True)
    for cmd in (['apt-get', 'update'], ['apt-get', 'install', '-y', 'unattended-upgrades']):
        result = subprocess.run(cmd, check=False)
        if result.returncode:
            raise SystemExit(f'Command failed with exit code {result.returncode}: {cmd[1]}')
    # Atomic exclusive creation prevents replacing existing configuration.
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
    print('Created', target, '\nReview /etc/apt/apt.conf.d/50unattended-upgrades and reboot policy.')

def main():
    ap = argparse.ArgumentParser(description='VPS security audit. Read-only unless apply --confirm is used.')
    ap.add_argument('--config', default=CONFIG_NAME, help='Local provider config path')
    ap.add_argument('--provider', choices=PROVIDERS, help='Override provider for this run')
    sub = ap.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='Interactively select provider and save local config')
    scan = sub.add_parser('scan', help='Run a read-only scan and generate reports')
    scan.add_argument('--output', default='./reports', help='Report output directory (contains sensitive metadata)')
    plan = sub.add_parser('plan', help='Show supported remediation plan (read-only)')
    fix = sub.add_parser('apply', help='Execute ONE allowlisted fix; explicit confirmation required')
    fix.add_argument('--fix', required=True, choices=['enable-unattended-upgrades'])
    fix.add_argument('--confirm', action='store_true')
    args = ap.parse_args()
    config_path = Path(args.config)
    if args.command == 'init':
        provider = args.provider or choose_provider()
        save_provider(provider, config_path)
        print(f'Configured: {provider} ({config_path})')
        return
    provider = args.provider or load_provider(config_path)
    if provider is None:
        if sys.stdin.isatty():
            provider = choose_provider()
            save_provider(provider, config_path)
            print(f'Configured: {provider} ({config_path})')
        else:
            provider = 'other'
            print('No provider configured; using other. Run python3 guard.py init', file=sys.stderr)
    if args.command == 'apply':
        apply_fix(args.fix, args.confirm)
        return
    data = audit(provider)
    if args.command == 'plan':
        print(json.dumps({'candidate_fixes': propose(data), 'manual_findings': [f['id'] for f in data['findings'] if f['status'] in ('fail', 'review', 'unknown') and not f['fix']]}, indent=2))
        return
    path = Path(args.output).expanduser().resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    for suffix, body in [('.json', json.dumps(data, indent=2) + '\n'), ('.md', markdown(data))]:
        filename = path / f'audit-{stamp}{suffix}'
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(body)
        print(filename)
    print('Summary:', json.dumps(summary(data), sort_keys=True))
    print('Important: unknown is not pass; provider settings need separate verification.')

if __name__ == '__main__':
    main()
