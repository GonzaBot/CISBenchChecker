# CISBenchChecker v1.0

**Agentless Linux hardening auditor for SSH, Nginx, and Apache.**

CISBenchChecker is a lightweight Python CLI that inspects critical Linux service configuration and compares it against practical CIS Benchmark-inspired hardening checks. It is built for lab technicians, cybersecurity students, system administrators, and portfolio projects where the goal is to understand, verify, and document secure server configuration without deploying a heavy enterprise scanner.

> Day 39 - 100 Cybersecurity Apps in 100 Days

## What Is A Linux Server?

A Linux server is a computer running Linux that provides a service over a network or the internet. A website, API, dashboard, internal tool, or application backend usually runs on a server.

Common services include:

- **SSH**: the remote administration service used to connect securely to the server.
- **Nginx**: a high-performance web server and reverse proxy.
- **Apache**: another widely used web server for serving websites and applications.

These services run continuously and are controlled by configuration files. Those files define who can connect, which cryptographic algorithms are allowed, how much information the server exposes, whether logs are created, and how the service behaves under load.

## What Is An Insecure Configuration?

Most services are designed to work immediately after installation. Default settings are convenient, but they are not always the safest baseline for an internet-facing server.

For example, SSH may allow direct `root` login if it is not hardened. `root` is the most powerful account on a Linux system. If attackers can try to log in as `root` from the internet, they can brute-force passwords or exploit weak credentials. A safer configuration blocks direct root login:

```text
PermitRootLogin no
```

With that setting, administrators first log in as a normal user and then elevate privileges when needed. Similar hardening rules exist for empty passwords, old encryption algorithms, weak TLS protocols, exposed server version banners, missing security headers, directory listing, request limits, and logging.

## What Is The CIS Benchmark?

The Center for Internet Security (CIS) publishes security configuration benchmarks maintained by security experts. These benchmarks are widely used by companies, auditors, and infrastructure teams as a baseline for hardening operating systems, cloud platforms, and services.

Manually reviewing a full benchmark can take hours because each service may have dozens of configuration items. You need to know which file to inspect, which directive matters, what value is acceptable, and how to reload the service safely.

## What CISBenchChecker Does

CISBenchChecker automates that workflow. It:

- Detects installed services.
- Reads SSH, Nginx, and Apache configuration.
- Runs 65 hardening checks.
- Marks each check as `PASS`, `FAIL`, `SKIP`, or `ERROR`.
- Shows the current value and expected secure value.
- Provides exact fix hints for failed checks.
- Calculates a score and grade per service.
- Exports reports to `JSON`, `CSV`, and dark-mode `HTML`.
- Supports local and remote SSH execution without installing an agent on the target.

Example output:

```text
SSH   Grade: C   Score: 61/100

PASS  PermitEmptyPasswords
FAIL  PermitRootLogin
      Current:  yes
      Expected: no
      Fix:      PermitRootLogin no

FAIL  MaxAuthTries
      Current:  6
      Expected: 4 or less
      Fix:      MaxAuthTries 4
```

## Features

- **Pure Python CLI**: simple to run, easy to inspect, and suitable for labs.
- **Agentless remote audits**: uses SSH through `paramiko`; nothing is installed on the target.
- **Smart service detection**: audits only the selected or detectable services.
- **CIS-inspired checks**: covers SSH authentication, SSH crypto, Nginx TLS/security headers, Apache hardening, logging, request limits, and more.
- **Actionable remediation**: failed checks include the target configuration file, directive, expected value, and reload command.
- **Professional reports**: terminal tables plus `reports/` exports in JSON, CSV, and HTML.

## Installation

### Linux

```bash
chmod +x setup.sh
./setup.sh
```

### macOS Controller

The audited target should be Linux. macOS can be used as a controller machine for remote SSH audits:

```bash
chmod +x setup.sh
./setup.sh
./venv/bin/python cisbench.py --ssh user@192.0.2.10 --key ~/.ssh/id_ed25519
```

### Windows Controller

Windows can also be used as a controller machine for remote SSH audits:

```bat
setup.bat
run.bat --ssh user@192.0.2.10 --key C:\Users\you\.ssh\id_ed25519
```

Manual installation:

```bash
python3 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
```

## Usage

Audit all detectable local services:

```bash
sudo ./venv/bin/python cisbench.py
```

Export an HTML report:

```bash
sudo ./venv/bin/python cisbench.py --export html
```

Audit only Nginx and show remediation hints:

```bash
sudo ./venv/bin/python cisbench.py --service nginx --verbose
```

Show only failed checks:

```bash
sudo ./venv/bin/python cisbench.py --only-fails --verbose
```

Run an agentless remote audit:

```bash
./venv/bin/python cisbench.py --ssh user@192.0.2.10 --key ~/.ssh/id_ed25519 --export all
```

On Windows, use `run.bat` with `--ssh` to audit a Linux target remotely.

For a full practical walkthrough, see [LAB_HANDS_ON_LINUX.md](LAB_HANDS_ON_LINUX.md).

## CLI Reference

| Option | Description |
| --- | --- |
| `--ssh user@host` | Run the audit on a remote Linux server over SSH. |
| `--key path` | SSH private key for remote authentication. |
| `--password value` | SSH password authentication. Not recommended for production use. |
| `--service ssh\|nginx\|apache\|all` | Select one service or audit all detectable services. |
| `--level 1\|2\|all` | Select CIS level. Level 1 is the default; `all` includes stricter Level 2 checks. |
| `--only-fails` | Print only failed checks in the terminal report. |
| `--export json\|csv\|html\|all` | Save reports under `reports/`. |
| `--verbose` | Show full fix hints in terminal output. |
| `--quiet` | Hide banner and terminal report. Useful for automation. |

## Exit Codes

- `0`: audit completed with no failed checks.
- `1`: audit completed and at least one scored check failed.
- `2`: CLI usage error from `argparse`.

## When To Use It

- **Work or lab environments**: verify that Linux servers are hardened before connecting them to a network.
- **Cybersecurity learning**: every failed check teaches a concrete hardening rule and how to fix it.
- **Portfolio projects**: demonstrates defensive security, Linux administration, secure configuration review, reporting, and Python automation.
- **Pre-audit preparation**: quickly identify obvious misconfigurations before a formal review.

## Notes And Limitations

CISBenchChecker is a practical learning and triage tool, not an official CIS certification product. Benchmark versions differ by distribution and service version, so always validate changes in a staging environment before applying them to production. Some checks require `sudo` because system configuration files may not be readable by normal users.

Generated reports, Python caches, virtual environments, and local Codex metadata are intentionally excluded through `.gitignore`.

## License

MIT License. Copyright Gonzabot.
