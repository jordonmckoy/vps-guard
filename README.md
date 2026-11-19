# VPS Guard

Small, dependency-free, **local** security posture audit and explicitly gated remediation helper for Debian/Ubuntu VPS hosts (Hetzner, DigitalOcean, or other). Python 3.9+.

**Default is read-only.** No commands are downloaded or piped into a shell. The toolkit does not phone home, install dependencies during a scan, change firewall rules, edit SSH, or restart services.

## Quick start

```bash
git clone https://github.com/YOUR-ACCOUNT/vps-guard.git
cd vps-guard
python3 guard.py init  # interactive provider selection
python3 guard.py scan
sudo python3 guard.py scan
python3 guard.py plan
```

The GitHub URL above is a **placeholder** until you publish this repo. Alternatively extract the ZIP artifact directly on the VPS. Run `python3 -m unittest discover -s tests -v` before first use.

Reports are written to `./reports/audit-YYYYMMDDTHHMMSSZ.json` and `.md` with restrictive local permissions. `reports/` is gitignored. **Do not post raw reports publicly:** they contain hostnames, ports, running services and package information. Output is not sent anywhere.

## Provider setup

Run `python3 guard.py init` (or an interactive `scan` with no config) to select:

```text
Which VPS provider do you use?
  1) Hetzner
  2) DigitalOcean
  3) Other
Select [1-3]:
```

The selection is saved to `.vps-guard.json` (gitignored). CLI overrides: `python3 guard.py --provider digitalocean scan`. In non-interactive environments without a config, `other` is used with a warning. Reconfigure by editing/deleting the local config and running `init` again. Cloud-provider API checks are **not yet implemented**; only provider-specific manual advice is added.

## Checks

- OS/kernel and privileges
- Listening TCP and UDP ports, highlighting wildcard bindings and common database/metrics ports
- Effective OpenSSH configuration (password, keyboard-interactive, root login, etc.)
- UFW status (host firewall only; cannot validate provider firewall)
- APT upgrade candidates (simulation; lists may be stale)
- Basic unattended-upgrades periodic configuration and service/timer state
- Docker container port publication, if accessible
- Tailscale backend availability
- Manual critical check: provider-side firewall, backups, disaster recovery

Check statuses: `pass`, `fail`, `review`, `unknown`. `unknown` is **not** a pass. A `fail` means a configuration warrants attention, not proof of exploitable vulnerability. `ss` cannot establish actual internet reachability.

## Remediation

Supported automated fix in v0.1: **enable unattended-upgrades** on Debian/Ubuntu hosts without an existing `/etc/apt/apt.conf.d/20auto-upgrades` file.

```bash
python3 guard.py plan
sudo python3 guard.py apply --fix enable-unattended-upgrades  # DRY RUN (no changes)
sudo python3 guard.py apply --fix enable-unattended-upgrades --confirm
```

The confirmed fix runs `apt-get update`, installs `unattended-upgrades`, and creates a basic periodic configuration file **only if it is absent**. Review repository security origins in `50unattended-upgrades` and unattended reboot settings. Package installation itself changes the host; schedule production changes appropriately. If an existing configuration is present, the tool **refuses to overwrite it**. Rollback means reviewing package changes and removing the newly created configuration if appropriate, not blindly reversing a system upgrade.

**Intentionally not automated:** SSH authentication changes, Cloud Firewall changes, UFW default-deny, Docker networking, Tailscale access, package upgrades, secret rotation, backups. These can cause lockouts/data loss and require environment-specific runbooks and independent verification.

## Suggested staged rollout

1. Confirm provider rescue console works and current off-server backups exist.
2. Run audit without root; then with `sudo` to improve inspection completeness.
3. Compare findings against known externally reachable ports from a different network.
4. Attach a provider firewall with vetted allow rules in the provider console.
5. Test Tailscale management in a **second session** before changing SSH exposure.
6. Make one reviewed change at a time, audit again, and save a private baseline.
7. Validate recovery and restore procedures.

## Known limits and safety

- This is a posture inventory, **not** a penetration test, malware detector, CVE scanner, SCA/SBOM scanner, cloud account auditor, intrusion detection system, or proof of security.
- Root access enables more complete checks but also increases operational risk; review source before running as root.
- Provider control-plane configuration cannot be verified locally; review firewall rules, backups, SSH keys, recovery and 2FA in the Cloud Console.
- UFW does not necessarily protect Docker-published ports. Prefer both provider firewall and container network isolation.
- This project is not an official product of any VPS provider.
- Audit evidence may contain deployment metadata; keep the reports private.

## Publishing as a repo

Create an empty **private** GitHub repository called `vps-guard`, then run locally in the extracted directory:

```bash
git init
git add .
git commit -m 'Initial safe VPS audit toolkit'
git branch -M main
git remote add origin git@github.com:YOUR-ACCOUNT/vps-guard.git
git push -u origin main
```

Clone to the VPS using your preferred authentication, or download an archive of the repo. Never embed GitHub tokens or private keys in source files.
