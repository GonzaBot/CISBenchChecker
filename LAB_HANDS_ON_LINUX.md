# CISBenchChecker Hands-On Linux Lab

This lab is a practical, step-by-step exercise for learning Linux server hardening with CISBenchChecker. It is designed for a Linux workstation or VM and walks through preparing a test server, installing services, scanning it, reading the report, applying fixes, and validating improvement.

> Recommended environment: a disposable Linux virtual machine. Do not intentionally weaken SSH, Nginx, or Apache on a production server.

## 1. Lab Goal

By the end of this lab, you will be able to:

- Understand what Linux services are being audited.
- Install and start SSH, Nginx, and Apache in a controlled environment.
- Run CISBenchChecker locally.
- Generate terminal, JSON, CSV, and HTML reports.
- Interpret failed checks.
- Apply basic hardening changes.
- Re-run the scanner and compare before/after results.

The main idea is simple: first you observe the server as it is, then you improve it, then you verify the result. That cycle is exactly how real defensive security work is done.

## 2. What You Are Auditing

A Linux server usually exposes services. A service is a program that keeps running in the background and accepts connections or performs system tasks.

In this lab, we focus on three common services:

- **SSH**: remote administration. This is how you connect to a Linux server from another machine.
- **Nginx**: web server and reverse proxy. Often used to serve websites or forward traffic to applications.
- **Apache**: another common web server, widely used in hosting and internal apps.

Each service has configuration files. Security hardening means changing those files so the service exposes less attack surface, uses safer protocols, logs useful events, and avoids dangerous defaults.

## 3. Why This Matters

Attackers often do not need a sophisticated exploit. Many compromises start with weak configuration:

- SSH allowing direct `root` login.
- Too many password attempts allowed.
- Old cryptographic algorithms enabled.
- Web servers exposing version banners.
- Missing security headers.
- Directory listing enabled.
- Weak TLS protocols allowed.

CIS Benchmarks are security configuration baselines. They tell administrators which settings should be changed to reduce risk. CISBenchChecker automates part of that review.

## 4. Lab Safety

Use one of these environments:

- A local VM in VirtualBox, VMware, KVM, or GNOME Boxes.
- A temporary cloud VM.
- A local Linux machine only if you are comfortable modifying service configuration.

Avoid doing this directly on your main daily-use system if you are not sure how to restore configuration files.

Before editing any config file, make backups:

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak 2>/dev/null || true
sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak 2>/dev/null || true
```

Backups matter because configuration mistakes can stop a service from starting. With a backup, recovery is simple.

## 5. Requirements

You need:

- Linux.
- Python 3.
- `sudo` privileges.
- Internet access to install packages.
- This CISBenchChecker project folder.

Check your Python version:

```bash
python3 --version
```

Update package metadata:

```bash
sudo apt update
```

The commands in this lab use Debian/Ubuntu-style package names. If you use Fedora, Arch, or another distro, adapt the package manager commands.

## 6. Install Test Services

Install SSH, Nginx, and Apache:

```bash
sudo apt install -y openssh-server nginx apache2
```

Enable and start SSH:

```bash
sudo systemctl enable --now ssh
```

Enable and start Nginx:

```bash
sudo systemctl enable --now nginx
```

Apache and Nginx both want port `80`, so only one can listen there at the same time unless you change ports. For this lab, keep Nginx active and stop Apache when needed:

```bash
sudo systemctl stop apache2
```

Why this matters: scanners can read configuration files even if services are not exposed publicly, but service detection may depend on installed binaries and valid configuration. Starting services also lets you validate reload commands later.

## 7. Verify Services

Check SSH:

```bash
systemctl status ssh --no-pager
```

Check Nginx:

```bash
systemctl status nginx --no-pager
```

Check Apache:

```bash
systemctl status apache2 --no-pager
```

If Apache is stopped because Nginx is using port `80`, that is fine for this lab.

Check listening ports:

```bash
sudo ss -tulpn
```

Important ports:

- `22/tcp`: SSH.
- `80/tcp`: HTTP.
- `443/tcp`: HTTPS.

Knowing which ports are open helps you understand the server's attack surface.

## 8. Install CISBenchChecker Dependencies

From the project directory:

```bash
chmod +x setup.sh
./setup.sh
```

This creates a Python virtual environment and installs:

- `rich`: nice terminal tables and panels.
- `paramiko`: SSH library used for remote audits.

Test the tool:

```bash
./venv/bin/python cisbench.py --help
```

If the help menu appears, the CLI is ready.

If you later publish this project to GitHub, do not commit the `venv/` directory. It is local machine state and can always be recreated from `requirements.txt`.

## 9. First Local Scan

Run a local scan:

```bash
sudo ./venv/bin/python cisbench.py
```

Why `sudo` matters: files such as `/etc/ssh/sshd_config` may not be readable by normal users. Without enough permissions, checks may return `ERROR` or incomplete results.

You should see one panel per detected service. Each panel includes:

- Grade.
- Score.
- Passed checks.
- Failed checks.
- Skipped checks.

Grades are useful for quick triage, but the failed checks are what you actually fix.

## 10. Run A More Focused Scan

Scan only SSH:

```bash
sudo ./venv/bin/python cisbench.py --service ssh --verbose
```

Show only failed checks:

```bash
sudo ./venv/bin/python cisbench.py --service ssh --only-fails --verbose
```

This is often the best working mode. It removes noise and shows only what needs attention.

## 11. Export Reports

Generate all report formats:

```bash
sudo ./venv/bin/python cisbench.py --export all
```

Reports are saved in:

```text
reports/
```

Typical files:

```text
reports/cisbench_YYYYMMDD_HHMMSS.json
reports/cisbench_YYYYMMDD_HHMMSS.csv
reports/cisbench_YYYYMMDD_HHMMSS.html
```

Why exports matter:

- **HTML** is best for human reading and portfolio screenshots.
- **JSON** is best for automation.
- **CSV** is best for spreadsheets, filtering, and simple audit tracking.

Open the HTML report from your file manager or browser.

Reports are evidence from your own machine. They are useful for screenshots and notes, but they should normally stay out of GitHub because they can contain hostnames, timestamps, paths, and security findings.

## 12. Understand The Report

Each check has:

- **ID**: benchmark-style identifier.
- **Level**: hardening level. Level 1 is safer for general use; Level 2 is stricter.
- **Title**: what is being checked.
- **Status**: `PASS`, `FAIL`, `SKIP`, or `ERROR`.
- **Current**: value found on the system.
- **Expected**: secure baseline value.
- **Fix**: line or command you should apply.

Status meaning:

- `PASS`: the current value matches the expected secure value.
- `FAIL`: the current value is insecure or missing.
- `SKIP`: the check was not applicable or not scored.
- `ERROR`: the tool could not read or evaluate the setting.

Do not blindly paste every fix into production. Understand what each setting does first.

## 13. SSH Hardening Exercise

Open the SSH server configuration:

```bash
sudo nano /etc/ssh/sshd_config
```

Add or update these lines:

```text
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
```

Why these matter:

- `PermitRootLogin no`: blocks direct login as the most powerful user.
- `PermitEmptyPasswords no`: prevents accounts with empty passwords from logging in.
- `X11Forwarding no`: disables graphical forwarding if you do not need it.
- `MaxAuthTries 4`: reduces brute-force attempts per connection.
- `ClientAliveInterval` and `ClientAliveCountMax`: disconnect idle sessions.
- `LoginGraceTime 60`: limits how long unauthenticated sessions can stay open.
- `AllowAgentForwarding no`: reduces risk if a remote host is compromised.
- `AllowTcpForwarding no`: disables SSH tunneling unless explicitly needed.
- `PermitUserEnvironment no`: prevents user-controlled environment injection.

Validate SSH configuration before restarting:

```bash
sudo sshd -t
```

If there is no output, syntax is valid.

Reload SSH:

```bash
sudo systemctl reload ssh
```

Important: if you are connected remotely over SSH, keep your current terminal open and test a new connection before closing it.

## 14. Nginx Hardening Exercise

Open Nginx configuration:

```bash
sudo nano /etc/nginx/nginx.conf
```

Inside the `http { ... }` block, add or update:

```nginx
server_tokens off;
client_max_body_size 1K;
keepalive_timeout 10;
autoindex off;

add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Why these matter:

- `server_tokens off`: hides the Nginx version from error pages and headers.
- `client_max_body_size`: limits oversized request bodies.
- `keepalive_timeout`: reduces resource exhaustion risk.
- `autoindex off`: prevents directory listing.
- `X-Frame-Options`: helps prevent clickjacking.
- `X-Content-Type-Options`: prevents MIME sniffing.
- `X-XSS-Protection`: legacy browser XSS filter header.
- `Strict-Transport-Security`: tells browsers to prefer HTTPS.

Validate Nginx:

```bash
sudo nginx -t
```

Reload Nginx:

```bash
sudo systemctl reload nginx
```

Note: HSTS should only be used when HTTPS is correctly configured. In a real production environment, do not enable HSTS casually unless the domain is ready for HTTPS-only access.

## 15. Apache Hardening Exercise

If you want to test Apache separately, stop Nginx and start Apache:

```bash
sudo systemctl stop nginx
sudo systemctl start apache2
```

Open Apache security configuration:

```bash
sudo nano /etc/apache2/conf-available/security.conf
```

Add or update:

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

Open the main Apache config:

```bash
sudo nano /etc/apache2/apache2.conf
```

Inside the root directory block, prefer:

```apache
<Directory />
    Options -Indexes
    AllowOverride None
    Require all denied
</Directory>
```

Why these matter:

- `ServerTokens Prod`: reduces server version disclosure.
- `ServerSignature Off`: hides Apache signature on generated pages.
- `TraceEnable Off`: disables HTTP TRACE, which is rarely needed.
- `Options -Indexes`: prevents directory listing.
- `AllowOverride None`: avoids unexpected `.htaccess` behavior.
- `Require all denied`: denies access at the filesystem root unless explicitly allowed elsewhere.

Validate Apache:

```bash
sudo apache2ctl configtest
```

Reload Apache:

```bash
sudo systemctl reload apache2
```

When done, you can switch back to Nginx:

```bash
sudo systemctl stop apache2
sudo systemctl start nginx
```

## 16. Second Scan: Verify Improvements

Run the same scan again:

```bash
sudo ./venv/bin/python cisbench.py --export all --verbose
```

Compare:

- Did the score improve?
- Did the grade change?
- Which checks still fail?
- Are failures caused by missing config, unsupported directives, or a real insecure setting?

This before/after comparison is the core of the exercise.

## 17. Analyze A Failed Check

Pick one failed check and answer:

1. What service does it affect?
2. What is the current value?
3. What is the expected value?
4. What risk does the current value create?
5. What exact file must be changed?
6. What command reloads the service?
7. Could this setting break a legitimate workflow?

Example:

```text
Check: PermitRootLogin
Current: yes
Expected: no
Risk: attackers can attempt direct root login.
File: /etc/ssh/sshd_config
Fix: PermitRootLogin no
Reload: sudo systemctl reload ssh
Possible impact: administrators must log in as a normal user first.
```

This is how you turn a scanner result into real security analysis.

## 18. Remote Audit Exercise

If you have a second Linux VM, audit it remotely.

From your scanner machine, create or use an SSH key:

```bash
ssh-keygen -t ed25519 -C "cisbench-lab"
```

Copy the key to the target:

```bash
ssh-copy-id user@TARGET_IP
```

Test SSH:

```bash
ssh user@TARGET_IP
```

Run CISBenchChecker remotely:

```bash
./venv/bin/python cisbench.py --ssh user@TARGET_IP --key ~/.ssh/id_ed25519 --export all
```

Why remote mode matters: in real audits, you often cannot install an agent on the server. Agentless scanning lets you inspect configuration over SSH using existing admin access.

## 19. Optional: Create A Deliberately Weak SSH Setting

Only do this in a disposable VM.

Edit SSH:

```bash
sudo nano /etc/ssh/sshd_config
```

Set:

```text
PermitRootLogin yes
MaxAuthTries 6
X11Forwarding yes
```

Validate and reload:

```bash
sudo sshd -t
sudo systemctl reload ssh
```

Scan again:

```bash
sudo ./venv/bin/python cisbench.py --service ssh --only-fails --verbose
```

You should see those insecure choices appear as failed checks. Then revert them:

```text
PermitRootLogin no
MaxAuthTries 4
X11Forwarding no
```

Validate, reload, and scan again.

This makes the learning concrete: you see how a config line changes the report.

## 20. Troubleshooting

### The scanner says a file cannot be read

Run with `sudo`:

```bash
sudo ./venv/bin/python cisbench.py
```

### Nginx and Apache conflict

They both use port `80` by default. Stop one before starting the other:

```bash
sudo systemctl stop nginx
sudo systemctl start apache2
```

or:

```bash
sudo systemctl stop apache2
sudo systemctl start nginx
```

### SSH reload fails

Check syntax:

```bash
sudo sshd -t
```

Then inspect logs:

```bash
journalctl -u ssh --no-pager -n 50
```

### Nginx reload fails

Check syntax:

```bash
sudo nginx -t
```

### Apache reload fails

Check syntax:

```bash
sudo apache2ctl configtest
```

## 21. Cleanup

Restore backups if needed:

```bash
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo systemctl reload ssh
```

For Nginx:

```bash
sudo cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
sudo nginx -t
sudo systemctl reload nginx
```

For Apache:

```bash
sudo cp /etc/apache2/apache2.conf.bak /etc/apache2/apache2.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Remove lab packages if this was only a test:

```bash
sudo apt remove -y nginx apache2 openssh-server
sudo apt autoremove -y
```

Only remove `openssh-server` if you do not need SSH access to that machine.

If this is a remote VM, confirm you have console access before removing SSH.

## 22. Lab Deliverables

For a portfolio or class submission, save:

- Screenshot of the first scan.
- HTML report from the first scan.
- Notes explaining three failed checks.
- The configuration lines you changed.
- Screenshot of the second scan.
- HTML report from the second scan.
- A short conclusion explaining what improved.

Suggested conclusion format:

```text
The initial scan showed weak SSH and web server defaults. After applying hardening changes such as disabling root SSH login, limiting authentication attempts, hiding web server version banners, and adding security headers, the server score improved. Remaining findings should be reviewed against the operating system version, application requirements, and production change-control policy.
```

## 23. Key Takeaways

- Hardening is configuration security.
- Scanners help you find issues, but you still need to understand impact.
- Always validate config syntax before reloading services.
- Always keep backups before editing system files.
- Re-scan after changes to prove improvement.
- A good report explains risk, evidence, fix, and validation.

This is the same defensive workflow used in real environments: baseline, analyze, remediate, validate, document.
