#!/usr/bin/env python3
"""VPS Guard: conservative, provider-agnostic local VPS security audit."""
import argparse
import datetime as dt
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys

VERSION = '0.3.0'
PROVIDERS = ('hetzner', 'digitalocean', 'other')
CONFIG_NAME = '.vps-guard.json'
RISKY_PORTS = {'2375', '2376', '3000', '3306', '5432', '6379', '9090', '9200', '27017'}
TAILSCALE_NETWORKS = (ipaddress.ip_network('100.64.0.0/10'), ipaddress.ip_network('fd7a:115c:a1e0::/48'))
EXPOSED_SCOPES = ('wildcard', 'public')
DOCKER_SOCKETS = ('/var/run/docker.sock', '/run/docker.sock')
KEY_EXPIRY_WARNING_DAYS = 30

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


class Host:
    """Runs local commands and records which probes could not complete."""

    def __init__(self):
        self.checks = {}

    def run(self, name, args, timeout=12):
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
            result = {'ok': p.returncode == 0, 'out': p.stdout.strip(), 'err': p.stderr.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as ex:
            result = {'ok': False, 'out': '', 'err': str(ex)}
        self.checks[name] = {'ok': result['ok'], 'error': '' if result['ok'] else result['err'][:250]}
        return result

    def run_json(self, name, args):
        result = self.run(name, args)
        try:
            return json.loads(result['out'] or '{}') if result['ok'] else None
        except ValueError:
            return None

def read_text(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return None

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

def address_scope(host):
    """Classify a bind address as wildcard, loopback, tailscale, private, public or unknown."""
    if host in ('', '0.0.0.0', '::', '*'):
        return 'wildcard'
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return 'unknown'
    if ip.is_loopback:
        return 'loopback'
    if any(ip in network for network in TAILSCALE_NETWORKS):
        return 'tailscale'
    if ip.is_private or ip.is_link_local:
        return 'private'
    return 'public'

def parse_ss(text):
    """Parse ss -H -lntup output. Endpoints look like 0.0.0.0:22, [::]:22, *:22 or 127.0.0.53%lo:53."""
    listeners = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0].lower() not in ('tcp', 'udp'):
            continue
        host, _, port = cols[4].rpartition(':')
        process = re.search(r'users:\(\("([^"]+)"', line)
        listeners.append({'protocol': cols[0].lower(), 'local': cols[4], 'port': port,
                          'scope': address_scope(host.split('%')[0].strip('[]')),
                          'process': process[1] if process else None})
    return listeners

def ufw_restricts_ssh(ufw_status, port):
    """True when UFW is active, denies inbound by default and allows SSH only on tailscale0."""
    text = ufw_status.lower()
    if 'status: active' not in text or not re.search(r'default: (deny|reject) \(incoming\)', text):
        return False
    public_allows = [line for line in text.splitlines() if 'allow' in line and 'tailscale0' not in line]
    return not any(re.match(rf'({port}(/tcp)?|openssh)\b', rule) for rule in public_allows)

def parse_go_time(value):
    """Parse Go's RFC 3339 timestamps (nanoseconds, Z suffix) on Python 3.9+."""
    return dt.datetime.fromisoformat(re.sub(r'\.\d+', '', value).replace('Z', '+00:00'))

def key_label(line):
    """Summarise an authorized_keys entry as key type and comment, without the key material."""
    match = re.search(r'((?:ssh|ecdsa|sk)-\S+)\s+\S+\s*(.*)', line)
    return f'{match[1]} {match[2]}'.strip() if match else 'unparsed entry'


def check_listeners(listeners, error):
    if listeners is None:
        yield finding('listeners', 'medium', 'unknown', 'Cannot enumerate listening ports', error,
                      'Install iproute2 or run with adequate privileges.')
        return
    exposed = [entry for entry in listeners if entry['scope'] in EXPOSED_SCOPES]
    risky = [entry for entry in exposed if entry['port'] in RISKY_PORTS]
    yield finding('listeners', 'high' if risky else 'info', 'fail' if risky else 'review' if exposed else 'pass',
        'Listening services on wildcard or public addresses',
        {'exposed': exposed, 'tailscale_only': [entry for entry in listeners if entry['scope'] == 'tailscale']},
        'Review each exposed listener, especially database, Docker API and metrics ports. Bind internal services to '
        '127.0.0.1 or the Tailscale IP, and validate actual internet reachability from outside the server.')

SSH_EXPECTED = [
    ('permitrootlogin', {'no'}, 'Root SSH login', 'high'),
    ('passwordauthentication', {'no'}, 'SSH password authentication', 'high'),
    ('kbdinteractiveauthentication', {'no'}, 'SSH keyboard-interactive authentication', 'high'),
    ('permitemptypasswords', {'no'}, 'Empty SSH passwords', 'critical'),
    ('pubkeyauthentication', {'yes'}, 'SSH public key authentication', 'medium'),
    ('x11forwarding', {'no'}, 'SSH X11 forwarding', 'low'),
]

def check_ssh(ssh, error):
    if ssh is None:
        yield finding('ssh', 'medium', 'unknown', 'Cannot inspect effective SSH config', error,
            'If OpenSSH server is installed, run with permission to inspect sshd -T; confirm whether SSH is actually in use.')
        return
    for key, safe, title, severity in SSH_EXPECTED:
        value = ssh.get(key, 'unknown')
        status = 'unknown' if value == 'unknown' else 'pass' if value in safe else 'fail'
        yield finding('ssh_' + key, severity, status, title, {'effective_value': value},
                      'Review SSH config and access requirements before applying changes.')
    tries = ssh.get('maxauthtries', 'unknown')
    yield finding('ssh_maxauthtries', 'low', 'pass' if tries.isdigit() and int(tries) <= 4 else 'review',
        'SSH authentication attempts per connection', {'effective_value': tries},
        'Set MaxAuthTries 3 or 4 to slow down brute-force attempts.')
    allowlist = {key: ssh[key] for key in ('allowusers', 'allowgroups') if key in ssh}
    yield finding('ssh_allowlist', 'low', 'pass' if allowlist else 'review', 'SSH login allowlist',
        allowlist or 'No AllowUsers or AllowGroups directive',
        'Restrict SSH to named admin accounts with AllowUsers or AllowGroups.')

def check_ssh_exposure(listeners, ssh, ufw_status, tailscale_running):
    port = (ssh or {}).get('port', '22')
    ssh_listeners = [entry for entry in listeners or [] if entry['protocol'] == 'tcp' and entry['port'] == port]
    exposed = [entry['local'] for entry in ssh_listeners if entry['scope'] in EXPOSED_SCOPES]
    restricted = ufw_status is not None and ufw_restricts_ssh(ufw_status, port)
    if listeners is None:
        status = 'unknown'
    elif not exposed or restricted:
        status = 'pass'
    elif tailscale_running and ufw_status is not None:
        status = 'fail'
    else:
        status = 'review'
    if tailscale_running:
        advice = (f'From a second session connected over Tailscale, run: sudo ufw allow in on tailscale0 to any port {port} '
                  f'proto tcp; then remove the public rule (sudo ufw delete allow OpenSSH or sudo ufw delete allow {port}/tcp) '
                  'and confirm you can still connect over Tailscale. Keep provider console access for recovery. Avoid '
                  'ListenAddress on the Tailscale IP: sshd can start before tailscaled and fail to bind at boot.')
    else:
        advice = ('Public SSH is normal without a private admin network: keep key-only auth and fail2ban, restrict '
                  'source IPs in the provider firewall, or move admin access to Tailscale.')
    yield finding('ssh_exposure', 'high', status, 'SSH reachable outside the private admin network',
        {'port': port, 'listening_on': [entry['local'] for entry in ssh_listeners], 'exposed': exposed,
         'ufw_restricts_to_tailscale0': restricted, 'tailscale_running': tailscale_running}, advice)

def check_authorized_keys():
    keys, unreadable = {}, []
    for user in pwd.getpwall():
        try:
            lines = (Path(user.pw_dir) / '.ssh' / 'authorized_keys').read_text(errors='replace').splitlines()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            unreadable.append(user.pw_name)
            continue
        entries = [key_label(line) for line in lines if line.strip() and not line.lstrip().startswith('#')]
        if entries:
            keys[user.pw_name] = entries
    yield finding('authorized_keys', 'medium', 'unknown' if unreadable else 'review' if keys else 'pass',
        'SSH authorized keys inventory', {'keys': keys, 'unreadable_accounts': unreadable},
        'Remove keys you cannot attribute to a current person or automation. Run with sudo to read every account.')

def check_fail2ban(host):
    active = host.run('fail2ban', ['systemctl', 'is-active', 'fail2ban'])['out'] == 'active'
    jails = 'not running'
    if active:
        jail_list = re.search(r'Jail list:\s*(.*)', host.run('fail2ban_jails', ['fail2ban-client', 'status'])['out'])
        jails = jail_list[1].replace(',', ' ').split() if jail_list else 'unknown (run with sudo)'
    yield finding('fail2ban', 'medium', 'pass' if active else 'review', 'fail2ban brute-force protection',
        {'active': active, 'jails': jails},
        'Install fail2ban (sudo apt-get install fail2ban) and make sure the sshd jail is enabled in /etc/fail2ban/jail.local.')

def check_firewall(host, ufw):
    if ufw['ok'] and 'status: active' in ufw['out'].lower():
        yield finding('firewall', 'medium', 'pass', 'Host firewall (UFW)', {'summary': ufw['out'][:3000]},
            'Use a correctly scoped host firewall and provider firewall where available. Check Docker published ports independently.')
        config = read_text('/etc/default/ufw')
        ipv6 = config is not None and bool(re.search(r'^IPV6=yes', config, re.M))
        yield finding('ufw_ipv6', 'medium', 'unknown' if config is None else 'pass' if ipv6 else 'fail',
            'UFW IPv6 filtering', {'ipv6_enabled': ipv6},
            'Set IPV6=yes in /etc/default/ufw and run sudo ufw reload so IPv6 traffic is filtered too.')
        return
    for name, args in (('nftables', ['nft', 'list', 'ruleset']), ('iptables', ['iptables', '-S'])):
        ruleset = host.run(name, args)
        if ruleset['ok'] and ruleset['out']:
            yield finding('firewall', 'medium', 'review', f'Host firewall ({name} ruleset, UFW not active)',
                {'ufw': ufw['out'] or ufw['err'], 'ruleset': ruleset['out'][:3000]},
                'Confirm the ruleset drops unsolicited inbound traffic by default; Docker adds its own rules, which are not a firewall.')
            return
    yield finding('firewall', 'medium', 'fail' if ufw['ok'] else 'unknown', 'No host firewall confirmed',
        {'ufw': ufw['out'] or ufw['err']},
        'Run with sudo to inspect UFW, nftables and iptables, or enable a default-deny host firewall.')

def check_updates(host):
    if not shutil.which('apt-get'):
        yield finding('updates', 'info', 'unknown', 'Could not simulate APT upgrades', 'Not Debian/Ubuntu or apt-get missing',
                      'Inspect package manager security updates manually.')
        return
    updates = host.run('updates', ['apt-get', '-s', 'upgrade'], 30)
    if not updates['ok']:
        yield finding('updates', 'info', 'unknown', 'Could not simulate APT upgrades', updates['err'],
                      'Inspect package manager security updates manually.')
        return
    upgrades = [line.split()[1] for line in updates['out'].splitlines() if line.startswith('Inst ')]
    yield finding('updates', 'medium', 'fail' if upgrades else 'pass', 'APT upgrade candidates',
        {'count': len(upgrades), 'packages': upgrades[:35]},
        'Review package updates; apt simulation may rely on stale lists. Do not auto-upgrade production workloads without a maintenance plan.')

def check_auto_updates(host):
    package = host.run('unattended_package', ['dpkg-query', '-W', '-f=${Status}', 'unattended-upgrades'])['out']
    service = host.run('unattended', ['systemctl', 'is-enabled', 'unattended-upgrades.service'])['out']
    timer = host.run('apt_timer', ['systemctl', 'is-enabled', 'apt-daily-upgrade.timer'])['out']
    periodic = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', read_text('/etc/apt/apt.conf.d/20auto-upgrades') or ''))
    installed = package == 'install ok installed'
    yield finding('auto_updates', 'medium', 'pass' if installed and periodic else 'review', 'Unattended upgrades configuration',
        {'package_installed': installed, 'periodic_config_enabled': periodic, 'service_enabled': service, 'timer_enabled': timer},
        'Verify unattended-upgrades is installed and configured with the desired security origins and reboot policy.',
        'enable-unattended-upgrades')

def check_reboot_required():
    required = Path('/var/run/reboot-required').exists()
    packages = (read_text('/var/run/reboot-required.pkgs') or '').split()
    yield finding('reboot_required', 'medium', 'fail' if required else 'pass', 'Pending reboot',
        {'reboot_required': required, 'packages': packages},
        'Reboot in a maintenance window so patched kernels and libraries are actually running.')

def check_accounts():
    extra_root = [user.pw_name for user in pwd.getpwall() if user.pw_uid == 0 and user.pw_name != 'root']
    yield finding('uid0_accounts', 'critical', 'fail' if extra_root else 'pass', 'Accounts with UID 0 besides root',
        extra_root, 'Every UID 0 account is root. Remove or renumber any you did not create deliberately.')

    shadow = read_text('/etc/shadow')
    empty = [fields[0] for fields in (line.split(':') for line in (shadow or '').splitlines())
             if len(fields) > 1 and fields[1] == '']
    yield finding('empty_passwords', 'critical', 'unknown' if shadow is None else 'fail' if empty else 'pass',
        'Accounts with empty passwords', empty if shadow is not None else 'Cannot read /etc/shadow (run with sudo)',
        'Lock these accounts (sudo passwd -l USER) or set a password.')

    sudoers = {str(path): read_text(path) for path in [Path('/etc/sudoers'), *sorted(Path('/etc/sudoers.d').glob('*'))]}
    nopasswd = [f'{path}: {line.strip()}' for path, text in sudoers.items() for line in (text or '').splitlines()
                if 'NOPASSWD' in line and not line.lstrip().startswith('#')]
    unreadable = None in sudoers.values()
    yield finding('sudo_nopasswd', 'medium', 'unknown' if unreadable else 'review' if nopasswd else 'pass',
        'Passwordless sudo rules', nopasswd if not unreadable else 'Cannot read sudoers (run with sudo)',
        'Passwordless sudo turns any compromise of these accounts into root. Keep it only for accounts that need it.')

    try:
        docker_members = grp.getgrnam('docker').gr_mem
    except KeyError:
        docker_members = []
    yield finding('docker_group', 'medium', 'review' if docker_members else 'pass', 'Members of the docker group',
        docker_members, 'docker group membership is equivalent to root; keep it limited to admin accounts.')

def check_docker(host):
    ps = host.run('docker', ['docker', 'ps', '-q'])
    if not ps['ok']:
        yield finding('docker', 'info', 'unknown', 'Docker inspection unavailable',
            ps['err'] or 'Docker not installed or daemon inaccessible',
            'If Docker is in use, rerun with permissions to query the Docker daemon.')
        return
    ids = ps['out'].split()
    containers = json.loads(host.run('docker_inspect', ['docker', 'inspect', *ids])['out'] or '[]') if ids else []
    published, isolation = {}, {}
    for container in containers:
        name = container['Name'].lstrip('/')
        config = container['HostConfig']
        ports = [f"{binding['HostIp'] or '*'}:{binding['HostPort']}->{port}"
                 for port, bindings in (container['NetworkSettings'].get('Ports') or {}).items()
                 for binding in bindings or [] if address_scope(binding['HostIp']) in EXPOSED_SCOPES]
        issues = [label for label, present in (
            ('privileged', config.get('Privileged')),
            ('host network', config.get('NetworkMode') == 'host'),
            ('docker socket mounted', any(mount.get('Source') in DOCKER_SOCKETS for mount in container.get('Mounts') or [])),
        ) if present]
        if ports:
            published[name] = ports
        if issues:
            isolation[name] = issues
    yield finding('docker_publish', 'high', 'fail' if published else 'pass',
        'Docker containers with wildcard or public published ports', published,
        'Publish only public reverse proxy ports. Bind internal services to 127.0.0.1 or the Tailscale IP '
        '(-p 100.x.y.z:5432:5432), or keep them on private Docker networks. UFW does not filter Docker-published ports.')
    yield finding('docker_isolation', 'high', 'fail' if isolation else 'pass',
        'Docker containers with host-level access', isolation,
        'Privileged mode, host networking and a mounted Docker socket each give a container root-equivalent access to the host. '
        'Remove them unless the container genuinely needs it.')

def check_time_sync(host):
    synced = host.run('time_sync', ['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])['out']
    yield finding('time_sync', 'low', 'pass' if synced == 'yes' else 'review', 'Clock synchronisation',
        {'ntp_synchronized': synced or 'unknown'},
        'Enable systemd-timesyncd or chrony; accurate time matters for logs, TLS and TOTP.')

def check_apparmor():
    enabled = (read_text('/sys/module/apparmor/parameters/enabled') or '').strip() == 'Y'
    yield finding('apparmor', 'low', 'pass' if enabled else 'review', 'AppArmor', {'enabled': enabled},
        'Keep AppArmor enabled (the Debian/Ubuntu default) so confined services stay restricted.')

def check_ip_forwarding(forwarding):
    enabled = '1' in forwarding.values()
    yield finding('ip_forwarding', 'low', 'review' if enabled else 'pass', 'Kernel IP forwarding', forwarding,
        'Forwarding is expected with Docker, Tailscale subnet routers or exit nodes; otherwise disable it via sysctl.')

def check_tailscale(host, status, forwarding):
    state = status.get('BackendState', 'unknown') if status is not None else 'not installed or inaccessible'
    if state != 'Running':
        yield finding('tailscale', 'info', 'review', 'Tailscale not running', {'backend_state': state},
            'Consider Tailscale for private management access instead of public SSH.')
        return
    yield finding('tailscale', 'info', 'pass', 'Tailscale administrative network',
        {'backend_state': state, 'tailscale_ips': status.get('TailscaleIPs')},
        'Prefer private admin access; verify ACLs, recovery and connectivity before disabling public SSH.')

    node = status.get('Self') or {}
    expiry = node.get('KeyExpiry')
    days_left = (parse_go_time(expiry) - dt.datetime.now(dt.timezone.utc)).days if expiry else None
    yield finding('tailscale_key_expiry', 'high',
        'pass' if expiry is None else 'fail' if days_left < KEY_EXPIRY_WARNING_DAYS else 'review',
        'Tailscale node key expiry', {'expires': expiry, 'days_left': days_left},
        'Disable key expiry for this server in the Tailscale admin console (tagged nodes have it disabled by default). '
        'An expired key drops the server off the tailnet and can lock you out once public SSH is closed.')

    tags = node.get('Tags') or []
    yield finding('tailscale_tags', 'medium', 'pass' if tags else 'review', 'Tailscale node tags', tags,
        'Tag servers (for example tag:server) so ACLs apply and the node does not depend on a personal user account.')

    boot = host.run('tailscaled_enabled', ['systemctl', 'is-enabled', 'tailscaled'])['out']
    yield finding('tailscale_boot', 'high', 'pass' if boot == 'enabled' else 'fail', 'tailscaled starts at boot',
        {'systemctl_is_enabled': boot or 'unknown'},
        'Run sudo systemctl enable tailscaled so the server rejoins the tailnet after a reboot.')

    health = status.get('Health') or []
    yield finding('tailscale_health', 'low', 'review' if health else 'pass', 'Tailscale health warnings', health,
        'Resolve the warnings reported by tailscale status.')

    prefs = host.run_json('tailscale_prefs', ['tailscale', 'debug', 'prefs'])
    running_latest = (status.get('ClientVersion') or {}).get('RunningLatest')
    auto_update = ((prefs or {}).get('AutoUpdate') or {}).get('Apply')
    yield finding('tailscale_updates', 'medium', 'pass' if running_latest or auto_update else 'review',
        'Tailscale client updates',
        {'version': status.get('Version'), 'running_latest': running_latest, 'auto_update': auto_update},
        'Enable auto-updates with sudo tailscale set --auto-update, or keep Tailscale updated with system packages.')

    if prefs is None:
        yield finding('tailscale_prefs', 'low', 'unknown', 'Tailscale preferences unavailable', 'tailscale debug prefs failed',
            'Run with sudo to inspect Tailscale SSH, advertised routes and auto-update settings.')
    else:
        routes = prefs.get('AdvertiseRoutes') or []
        yield finding('tailscale_routes', 'medium', 'review' if routes else 'pass', 'Tailscale subnet routes and exit node',
            {'advertised_routes': routes, 'ip_forwarding': forwarding},
            'This node forwards traffic for the tailnet. Confirm ACLs limit who can use these routes and that '
            '0.0.0.0/0 (exit node) is intentional.')
        yield finding('tailscale_ssh', 'info', 'review' if prefs.get('RunSSH') else 'pass', 'Tailscale SSH',
            {'enabled': bool(prefs.get('RunSSH'))},
            'If all admin access goes through Tailscale SSH, OpenSSH can be firewalled off or disabled. '
            'Keep provider console access for recovery.')

    serve = host.run_json('tailscale_serve', ['tailscale', 'serve', 'status', '--json'])
    funnel = [target for target, allowed in ((serve or {}).get('AllowFunnel') or {}).items() if allowed]
    yield finding('tailscale_funnel', 'high', 'unknown' if serve is None else 'review' if funnel else 'pass',
        'Services published to the internet with Tailscale Funnel', funnel,
        'Funnel exposes services to the public internet, bypassing the host and provider firewalls. Confirm each is intentional.')

    yield finding('tailscale_admin_controls', 'high', 'unknown', 'Tailscale ACLs and tailnet settings',
        {'tailnet': (status.get('CurrentTailnet') or {}).get('Name'), 'checked_via_api': False},
        'Check the Tailscale admin console: ACLs or grants limit who can reach this server, device approval is on, '
        'tag owners are restricted, and admin accounts use MFA.')


def audit(provider='other'):
    host = Host()
    info = {'hostname': socket.gethostname(), 'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'version': VERSION, 'provider': provider, 'root': os.geteuid() == 0, 'checks': host.checks,
            'os': (read_text('/etc/os-release') or 'unknown')[:2000],
            'kernel': host.run('kernel', ['uname', '-r'])['out']}

    ss = host.run('listeners', ['ss', '-H', '-lntup'])
    listeners = parse_ss(ss['out']) if ss['ok'] else None
    info['listening'] = listeners
    sshd = host.run('ssh_effective', [shutil.which('sshd') or '/usr/sbin/sshd', '-T'])
    ssh = ssh_values(sshd['out']) if sshd['ok'] else None
    ufw = host.run('ufw', ['ufw', 'status', 'verbose'])
    tailscale = host.run_json('tailscale', ['tailscale', 'status', '--json'])
    tailscale_running = (tailscale or {}).get('BackendState') == 'Running'
    forwarding = {'ipv4': (read_text('/proc/sys/net/ipv4/ip_forward') or 'unknown').strip(),
                  'ipv6': (read_text('/proc/sys/net/ipv6/conf/all/forwarding') or 'unknown').strip()}

    findings = [
        *check_listeners(listeners, ss['err']),
        *check_ssh(ssh, sshd['err']),
        *check_ssh_exposure(listeners, ssh, ufw['out'] if ufw['ok'] else None, tailscale_running),
        *check_authorized_keys(),
        *check_fail2ban(host),
        *check_firewall(host, ufw),
        *check_updates(host),
        *check_auto_updates(host),
        *check_reboot_required(),
        *check_accounts(),
        *check_docker(host),
        *check_tailscale(host, tailscale, forwarding),
        *check_time_sync(host),
        *check_apparmor(),
        *check_ip_forwarding(forwarding),
        finding('privilege', 'info', 'review', 'Audit execution privileges', {'euid': os.geteuid()},
            'Running with sudo improves visibility but reports can contain sensitive infrastructure metadata.'),
        finding('provider_controls', 'high', 'unknown', 'Provider firewall and backups',
            {'provider': provider, 'checked_via_api': False}, provider_advice(provider)),
    ]
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
                '- This tool does not test external reachability, provider or Tailscale account security, image CVEs or application logic.',
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
    scan = sub.add_parser('scan', help='Run a read-only scan and generate reports; exits 1 if any check fails')
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
        return 0
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
        return 0
    data = audit(provider)
    if args.command == 'plan':
        print(json.dumps({'candidate_fixes': propose(data), 'manual_findings': [f['id'] for f in data['findings'] if f['status'] in ('fail', 'review', 'unknown') and not f['fix']]}, indent=2))
        return 0
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
    counts = summary(data)
    print('Summary:', json.dumps(counts, sort_keys=True))
    print('Important: unknown is not pass; provider settings need separate verification.')
    return 1 if counts.get('fail') else 0

if __name__ == '__main__':
    sys.exit(main())
