#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISBenchChecker v1.0 - Day 39 of 100 Cybersecurity Apps in 100 Days
Auditoría de seguridad para SSH, Nginx y Apache contra CIS Benchmarks.
Copyright Gonzabot. MIT License.
"""

import os
import sys
import argparse
import subprocess
import json
import csv
import re
import getpass
import html as html_lib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("Error: 'rich' library is required. Run setup.sh or pip install rich.")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    status: str          # PASS, FAIL, SKIP, ERROR
    current: str
    expected: str
    details: str

@dataclass
class Check:
    id: str
    title: str
    level: int
    scored: bool
    check_fn: Callable[['Executor'], CheckResult]
    fix: str
    config_file: str
    reload_cmd: str

@dataclass
class ServiceResult:
    score: float = 0.0
    grade: str = "F"
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    checks: List[Dict] = field(default_factory=list)

@dataclass
class AuditResult:
    target: str
    timestamp: str
    services: Dict[str, ServiceResult] = field(default_factory=dict)
    overall_score: float = 0.0

# ═══════════════════════════════════════════════════════════
# EXECUTOR LAYER
# ═══════════════════════════════════════════════════════════

class Executor:
    def execute(self, cmd: str) -> Tuple[str, str, int]:
        raise NotImplementedError

class LocalExecutor(Executor):
    def execute(self, cmd: str) -> Tuple[str, str, int]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), 1

class RemoteExecutor(Executor):
    def __init__(self, target: str, key_filename: str = None, password: str = None):
        try:
            import paramiko
        except ImportError:
            print("Error: 'paramiko' library is required for remote execution. pip install paramiko")
            sys.exit(1)
        
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        user, host = target.rsplit('@', 1) if '@' in target else (getpass.getuser(), target)
        
        try:
            self.client.connect(hostname=host, username=user, key_filename=key_filename, password=password)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            sys.exit(1)

    def execute(self, cmd: str) -> Tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        return stdout.read().decode('utf-8').strip(), stderr.read().decode('utf-8').strip(), exit_status

# ═══════════════════════════════════════════════════════════
# SERVICE DETECTION
# ═══════════════════════════════════════════════════════════

def detect_service(executor: Executor, service: str) -> bool:
    if service == "ssh":
        out, _, code = executor.execute("sshd -T 2>/dev/null || cat /etc/ssh/sshd_config >/dev/null 2>&1")
        return code == 0
    elif service == "nginx":
        out, _, code = executor.execute("which nginx || nginx -v >/dev/null 2>&1")
        return code == 0
    elif service == "apache":
        out, _, code = executor.execute("which apache2 || which httpd || apache2 -v >/dev/null 2>&1")
        return code == 0
    return False

# ═══════════════════════════════════════════════════════════
# GENERIC CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════

def generic_regex_check(
    executor: Executor,
    file_cmd: str,
    regex: str,
    expected: str,
    default: str = "Not Found",
    validator: Callable[[str, str], bool] = None
) -> CheckResult:
    out, err, code = executor.execute(file_cmd)
    if code != 0 and not out:
        return CheckResult("ERROR", "File read error", expected, err)
    
    match = re.search(regex, out, re.IGNORECASE | re.MULTILINE)
    if match:
        current = match.group(1).strip()
        is_valid = validator(current, expected) if validator else current.lower() == expected.lower()
        if is_valid:
            return CheckResult("PASS", current, expected, f"Matches expected value: {expected}")
        else:
            return CheckResult("FAIL", current, expected, f"Found {current}, expected {expected}")
    else:
        return CheckResult("FAIL", default, expected, f"Configuration not found. Expected: {expected}")

def check_file_permissions(executor: Executor, filepath: str, expected_perms: str, expected_owner: str) -> CheckResult:
    cmd = f"stat -c '%a %U:%G' {filepath} 2>/dev/null"
    out, err, code = executor.execute(cmd)
    if code != 0:
        return CheckResult("ERROR", "Not Found", f"{expected_perms} {expected_owner}", "File missing or no permission")
    
    current_perms = out.split()[0]
    current_owner = out.split()[1]
    
    if current_perms == expected_perms and current_owner == expected_owner:
        return CheckResult("PASS", f"{current_perms} {current_owner}", f"{expected_perms} {expected_owner}", "Permissions OK")
    return CheckResult("FAIL", f"{current_perms} {current_owner}", f"{expected_perms} {expected_owner}", "Incorrect permissions")

def equals_casefold(current: str, expected: str) -> bool:
    return current.casefold() == expected.casefold()

def max_int(current: str, expected: str) -> bool:
    try:
        return int(current) <= int(expected)
    except ValueError:
        return False

def min_int(current: str, expected: str) -> bool:
    try:
        return int(current) >= int(expected)
    except ValueError:
        return False

def contains_all_words(current: str, expected: str) -> bool:
    current_parts = set(re.split(r"\s+", current.casefold().strip()))
    expected_parts = set(re.split(r"\s+", expected.casefold().strip()))
    return expected_parts.issubset(current_parts)

def contains_secure_csv(current: str, expected: str) -> bool:
    current_items = {item.strip().casefold() for item in current.split(",") if item.strip()}
    expected_items = {item.strip().casefold() for item in expected.split(",") if item.strip()}
    return bool(current_items) and current_items.issubset(expected_items)

def directive_from_regex(regex: str) -> str:
    return regex.split(r"\s+", 1)[0].replace("^", "")

# ═══════════════════════════════════════════════════════════
# AUDITORS CONFIGURATION
# ═══════════════════════════════════════════════════════════

def build_ssh_checks() -> List[Check]:
    checks = []
    ssh_file = "/etc/ssh/sshd_config"
    cat_cmd = f"sshd -T 2>/dev/null || grep -vE '^[[:space:]]*#' {ssh_file} 2>/dev/null"
    reload_cmd = "systemctl reload sshd"

    checks.append(Check("5.2.1", "sshd_config permissions", 1, True, 
        lambda e: check_file_permissions(e, ssh_file, "600", "root:root"), "chmod 600 /etc/ssh/sshd_config\nchown root:root /etc/ssh/sshd_config", ssh_file, reload_cmd))

    ssh_settings = [
        ("5.2.2", "Protocol version", 1, r"Protocol\s+(\d)", "2"),
        ("5.2.3", "LogLevel", 1, r"LogLevel\s+(\w+)", "INFO"), # or VERBOSE
        ("5.2.4", "X11Forwarding", 1, r"X11Forwarding\s+(\w+)", "no"),
        ("5.2.5", "MaxAuthTries", 1, r"MaxAuthTries\s+(\d+)", "4"),
        ("5.2.6", "IgnoreRhosts", 1, r"IgnoreRhosts\s+(\w+)", "yes"),
        ("5.2.7", "HostbasedAuthentication", 1, r"HostbasedAuthentication\s+(\w+)", "no"),
        ("5.2.8", "PermitRootLogin", 1, r"PermitRootLogin\s+(\S+)", "no"),
        ("5.2.9", "PermitEmptyPasswords", 1, r"PermitEmptyPasswords\s+(\w+)", "no"),
        ("5.2.10", "PermitUserEnvironment", 1, r"PermitUserEnvironment\s+(\w+)", "no"),
        ("5.2.11", "Ciphers", 1, r"Ciphers\s+(.+)", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"),
        ("5.2.12", "MACs", 1, r"MACs\s+(.+)", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"),
        ("5.2.13", "KexAlgorithms", 1, r"KexAlgorithms\s+(.+)", "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"),
        ("5.2.14", "ClientAliveInterval", 1, r"ClientAliveInterval\s+(\d+)", "300"),
        ("5.2.15", "ClientAliveCountMax", 1, r"ClientAliveCountMax\s+(\d+)", "3"),
        ("5.2.16", "LoginGraceTime", 1, r"LoginGraceTime\s+(\d+)", "60"),
        ("5.2.17", "AllowTcpForwarding", 1, r"AllowTcpForwarding\s+(\w+)", "no"),
        ("5.2.18", "Banner", 1, r"Banner\s+(.+)", "/etc/issue.net"),
        ("5.2.19", "MaxStartups", 1, r"MaxStartups\s+(.+)", "10:30:60"),
        ("5.2.20", "MaxSessions", 1, r"MaxSessions\s+(\d+)", "10"),
        ("5.2.21", "UsePAM", 1, r"UsePAM\s+(\w+)", "yes"),
        ("5.2.22", "AllowAgentForwarding", 1, r"AllowAgentForwarding\s+(\w+)", "no"),
        ("5.2.23", "KerberosAuthentication", 1, r"KerberosAuthentication\s+(\w+)", "no"),
        ("5.2.24", "GSSAPIAuthentication", 1, r"GSSAPIAuthentication\s+(\w+)", "no"),
        ("5.2.25", "PrintMotd", 1, r"PrintMotd\s+(\w+)", "no")
    ]

    max_value_checks = {"5.2.5", "5.2.14", "5.2.15", "5.2.16", "5.2.20"}
    secure_csv_checks = {"5.2.11", "5.2.12", "5.2.13"}

    for id_, title, level, regex, expected in ssh_settings:
        validator = max_int if id_ in max_value_checks else contains_secure_csv if id_ in secure_csv_checks else equals_casefold
        fix_str = f"{directive_from_regex(regex)} {expected}"
        checks.append(Check(id_, title, level, True, 
            lambda e, r=regex, ex=expected, v=validator: generic_regex_check(e, cat_cmd, r, ex, validator=v), fix_str, ssh_file, reload_cmd))
    
    return checks

def build_nginx_checks() -> List[Check]:
    checks = []
    # Usando nginx -T para dumpear toda la config parseada
    cmd = "nginx -T 2>/dev/null"
    conf_file = "/etc/nginx/nginx.conf"
    reload_cmd = "nginx -s reload"

    nginx_settings = [
        ("4.1.1", "server_tokens", 1, r"server_tokens\s+(on|off);", "off"),
        ("4.1.2", "client_max_body_size", 1, r"client_max_body_size\s+(\w+);", "1K"), # Example tight baseline
        ("4.1.3", "keepalive_timeout", 1, r"keepalive_timeout\s+(\d+);", "10"),
        ("4.1.4", "autoindex", 1, r"autoindex\s+(on|off);", "off"),
        ("4.1.5", "ssl_protocols", 1, r"ssl_protocols\s+(.+?);", "TLSv1.2 TLSv1.3"),
        ("4.1.6", "ssl_ciphers", 1, r"ssl_ciphers\s+(.+?);", "HIGH:!aNULL:!MD5"),
        ("4.1.7", "ssl_prefer_server_ciphers", 1, r"ssl_prefer_server_ciphers\s+(on|off);", "on"),
        ("4.1.8", "X-Frame-Options header", 1, r"add_header\s+X-Frame-Options\s+[\"']?(SAMEORIGIN|DENY)[\"']?", "SAMEORIGIN"),
        ("4.1.9", "X-Content-Type-Options", 1, r"add_header\s+X-Content-Type-Options\s+[\"']?(nosniff)[\"']?", "nosniff"),
        ("4.1.10", "X-XSS-Protection", 1, r"add_header\s+X-XSS-Protection\s+[\"']?(1;\s*mode=block)[\"']?", "1; mode=block"),
        ("4.1.11", "Strict-Transport-Security", 1, r"add_header\s+Strict-Transport-Security\s+[\"']?(max-age=\d+;.*?)[\"']?", "max-age=31536000; includeSubDomains"),
        ("4.1.12", "worker_processes", 1, r"worker_processes\s+(auto|\d+);", "auto"),
        ("4.1.13", "access_log", 1, r"access_log\s+(.+?);", "/var/log/nginx/access.log"),
        ("4.1.14", "error_log", 1, r"error_log\s+(.+?);", "/var/log/nginx/error.log warn"),
        ("4.1.15", "client_body_buffer_size", 2, r"client_body_buffer_size\s+(\w+);", "1k"),
        ("4.1.16", "client_header_buffer_size", 2, r"client_header_buffer_size\s+(\w+);", "1k"),
        ("4.1.17", "large_client_header_buffers", 2, r"large_client_header_buffers\s+(\w+);", "2 1k"),
        ("4.1.18", "limit_conn_zone", 2, r"limit_conn_zone\s+(.+?);", "$binary_remote_addr zone=default:10m"),
        ("4.1.19", "limit_req_zone", 2, r"limit_req_zone\s+(.+?);", "$binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s"),
        ("4.1.20", "Hide Nginx version (FastCGI)", 1, r"fastcgi_hide_header\s+(X-Powered-By);", "X-Powered-By"),
    ]

    word_list_checks = {"4.1.5", "4.1.11"}

    for id_, title, level, regex, expected in nginx_settings:
        validator = contains_all_words if id_ in word_list_checks else equals_casefold
        fix_str = f"{directive_from_regex(regex)} {expected};"
        checks.append(Check(id_, title, level, True, 
            lambda e, r=regex, ex=expected, v=validator: generic_regex_check(e, cmd, r, ex, validator=v), fix_str, conf_file, reload_cmd))
    
    return checks

def build_apache_checks() -> List[Check]:
    checks = []
    cmd = "cat /etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*#'"
    conf_file = "/etc/apache2/apache2.conf"
    reload_cmd = "systemctl reload apache2"

    apache_settings = [
        ("3.1.1", "ServerTokens", 1, r"ServerTokens\s+(\w+)", "Prod"),
        ("3.1.2", "ServerSignature", 1, r"ServerSignature\s+(\w+)", "Off"),
        ("3.1.3", "TraceEnable", 1, r"TraceEnable\s+(\w+)", "Off"),
        ("3.1.4", "Options -Indexes", 1, r"Options\s+(.*Indexes.*)", "-Indexes"),
        ("3.1.5", "FileETag", 1, r"FileETag\s+(\w+)", "None"),
        ("3.1.6", "SSLProtocol", 1, r"SSLProtocol\s+(.+)", "all -SSLv3 -TLSv1 -TLSv1.1"),
        ("3.1.7", "SSLCipherSuite", 1, r"SSLCipherSuite\s+(.+)", "HIGH:!aNULL:!MD5:!3DES"),
        ("3.1.8", "SSLHonorCipherOrder", 1, r"SSLHonorCipherOrder\s+(\w+)", "On"),
        ("3.1.9", "Header X-Frame-Options", 1, r"Header\s+always\s+append\s+X-Frame-Options\s+[\"']?(SAMEORIGIN)[\"']?", "SAMEORIGIN"),
        ("3.1.10", "Header X-Content-Type-Options", 1, r"Header\s+always\s+set\s+X-Content-Type-Options\s+[\"']?(nosniff)[\"']?", "nosniff"),
        ("3.1.11", "Header X-XSS-Protection", 1, r"Header\s+always\s+set\s+X-XSS-Protection\s+[\"']?(1;\s*mode=block)[\"']?", "1; mode=block"),
        ("3.1.12", "LogLevel", 1, r"LogLevel\s+(\w+)", "warn"),
        ("3.1.13", "Timeout", 1, r"Timeout\s+(\d+)", "60"),
        ("3.1.14", "KeepAlive", 1, r"KeepAlive\s+(\w+)", "On"),
        ("3.1.15", "MaxKeepAliveRequests", 1, r"MaxKeepAliveRequests\s+(\d+)", "100"),
        ("3.1.16", "KeepAliveTimeout", 1, r"KeepAliveTimeout\s+(\d+)", "5"),
        ("3.1.17", "LimitRequestBody", 2, r"LimitRequestBody\s+(\d+)", "1048576"),
        ("3.1.18", "RequestReadTimeout", 2, r"RequestReadTimeout\s+(.+)", "header=20-40,MinRate=500 body=20,MinRate=500"),
        ("3.1.19", "AllowOverride", 1, r"AllowOverride\s+(\w+)", "None"),
        ("3.1.20", "Require all denied (Root)", 1, r"Require\s+(all\s+denied)", "all denied"),
    ]

    max_value_checks = {"3.1.13", "3.1.16", "3.1.17"}
    min_value_checks = {"3.1.15"}
    word_list_checks = {"3.1.6", "3.1.7", "3.1.18"}

    for id_, title, level, regex, expected in apache_settings:
        if id_ in max_value_checks:
            validator = max_int
        elif id_ in min_value_checks:
            validator = min_int
        elif id_ in word_list_checks:
            validator = contains_all_words
        else:
            validator = equals_casefold
        fix_str = f"{directive_from_regex(regex)} {expected}"
        checks.append(Check(id_, title, level, True, 
            lambda e, r=regex, ex=expected, v=validator: generic_regex_check(e, cmd, r, ex, validator=v), fix_str, conf_file, reload_cmd))
    
    return checks

# ═══════════════════════════════════════════════════════════
# CORE ENGINE
# ═══════════════════════════════════════════════════════════

def get_grade(score: float) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"

def run_audit(executor: Executor, services_to_run: List[str], target_level: int, console: Console) -> AuditResult:
    target = executor.client.get_transport().getpeername()[0] if isinstance(executor, RemoteExecutor) else "localhost"
    audit_result = AuditResult(target=target, timestamp=datetime.now().isoformat())
    
    auditors = {
        "ssh": build_ssh_checks(),
        "nginx": build_nginx_checks(),
        "apache": build_apache_checks()
    }

    total_passed = 0
    total_scored = 0

    for srv in services_to_run:
        console.print(f"\n[cyan]▶ Auditing {srv.upper()}...[/cyan]")
        if not detect_service(executor, srv):
            console.print(f"[yellow]  ↳ Skipped: {srv.upper()} not installed or not detectable.[/yellow]")
            continue
        
        srv_result = ServiceResult()
        checks_passed = 0
        checks_total = 0

        for check in auditors[srv]:
            if target_level != 0 and check.level > target_level:
                continue
            
            res = check.check_fn(executor)
            
            check_dict = {
                "id": check.id,
                "title": check.title,
                "level": check.level,
                "status": res.status,
                "current": res.current,
                "expected": res.expected,
                "fix": check.fix,
                "config_file": check.config_file,
                "reload_cmd": check.reload_cmd,
                "details": res.details
            }
            srv_result.checks.append(check_dict)

            if check.scored:
                checks_total += 1
                if res.status == "PASS":
                    checks_passed += 1
                    srv_result.passed += 1
                elif res.status == "FAIL":
                    srv_result.failed += 1
                else:
                    srv_result.skipped += 1

        if checks_total > 0:
            srv_result.score = (checks_passed / checks_total) * 100
            srv_result.grade = get_grade(srv_result.score)
            total_passed += checks_passed
            total_scored += checks_total

        audit_result.services[srv] = srv_result

    if total_scored > 0:
        audit_result.overall_score = (total_passed / total_scored) * 100

    return audit_result

# ═══════════════════════════════════════════════════════════
# REPORTING & EXPORT
# ═══════════════════════════════════════════════════════════

def print_terminal_report(audit: AuditResult, console: Console, only_fails: bool, verbose: bool):
    for srv, res in audit.services.items():
        color = "green" if res.score >= 80 else "yellow" if res.score >= 60 else "red"
        
        panel_content = f"Grade: [bold {color}]{res.grade}[/bold {color}] | Score: {res.score:.1f}%\n"
        panel_content += f"[green]✓ {res.passed} passed[/green]  [red]✗ {res.failed} failed[/red]  [gray]⊘ {res.skipped} skipped[/gray]"
        console.print(Panel(panel_content, title=f"[bold]{srv.upper()}[/bold]", expand=False, border_style=color))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Lv", justify="center", width=4)
        table.add_column("Title")
        table.add_column("Status", justify="center", width=8)
        table.add_column("Current")
        if verbose:
            table.add_column("Fix Instruction", style="dim")

        for c in res.checks:
            if only_fails and c["status"] != "FAIL":
                continue
            
            status_str = f"[green]✓ PASS[/green]" if c["status"] == "PASS" else \
                         f"[red]✗ FAIL[/red]" if c["status"] == "FAIL" else \
                         f"[yellow]⚠ {c['status']}[/yellow]"
            
            row = [c["id"], str(c["level"]), c["title"], status_str, c["current"]]
            if verbose:
                fix_text = f"Add to {c['config_file']}:\n  {c['fix']}\nThen run: {c['reload_cmd']}" if c["status"] == "FAIL" else "—"
                row.append(fix_text)
            
            table.add_row(*row)

        console.print(table)
        console.print("\n")

def export_json(audit: AuditResult, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(audit.__dict__, f, default=lambda o: o.__dict__, indent=2)

def export_csv(audit: AuditResult, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "ID", "Level", "Title", "Status", "Current", "Expected", "Fix"])
        for srv, res in audit.services.items():
            for c in res.checks:
                writer.writerow([srv, c["id"], c["level"], c["title"], c["status"], c["current"], c["expected"], c["fix"]])

def export_html(audit: AuditResult, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    safe_target = html_lib.escape(audit.target)
    safe_timestamp = html_lib.escape(audit.timestamp)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CISBench Audit Report - {safe_target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #ffffff; }}
        .header {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #00acc1; }}
        .card-container {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .card {{ background: #1e1e1e; padding: 15px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #333; }}
        .grade-A {{ color: #4caf50; }} .grade-B {{ color: #8bc34a; }} .grade-C {{ color: #ffeb3b; }} .grade-D {{ color: #ff9800; }} .grade-F {{ color: #f44336; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background-color: #2c2c2c; color: #00acc1; }}
        .PASS {{ color: #4caf50; font-weight: bold; }} .FAIL {{ color: #f44336; font-weight: bold; }} .SKIP, .ERROR {{ color: #9e9e9e; }}
        .fix-box {{ background: #000; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; margin-top: 5px; color: #00acc1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CIS Benchmark Security Audit</h1>
        <p><strong>Target:</strong> {safe_target} | <strong>Date:</strong> {safe_timestamp} | <strong>Overall Score:</strong> {audit.overall_score:.1f}%</p>
    </div>
"""
    for srv, res in audit.services.items():
        grade_class = f"grade-{res.grade.replace('+', '')}"
        safe_srv = html_lib.escape(srv.upper())
        html += f"""
    <h2>Service: {safe_srv}</h2>
    <div class="card-container">
        <div class="card"><h3 class="{grade_class}">{res.grade}</h3><p>Grade</p></div>
        <div class="card"><h3>{res.score:.1f}%</h3><p>Score</p></div>
        <div class="card"><h3 style="color:#4caf50;">{res.passed}</h3><p>Passed</p></div>
        <div class="card"><h3 style="color:#f44336;">{res.failed}</h3><p>Failed</p></div>
    </div>
    <table>
        <tr><th>ID</th><th>Level</th><th>Title</th><th>Status</th><th>Current</th><th>Fix Hint</th></tr>
"""
        for c in res.checks:
            safe_fix = html_lib.escape(c["fix"]).replace("\n", "<br>")
            safe_file = html_lib.escape(c["config_file"])
            fix_html = f"<div class='fix-box'>{safe_fix}<br><span style='color:#777;'>File: {safe_file}</span></div>" if c["status"] == "FAIL" else ""
            html += (
                f"<tr><td>{html_lib.escape(c['id'])}</td><td>{c['level']}</td>"
                f"<td>{html_lib.escape(c['title'])}</td><td class='{html_lib.escape(c['status'])}'>{html_lib.escape(c['status'])}</td>"
                f"<td>{html_lib.escape(c['current'])}</td><td>{fix_html}</td></tr>"
            )
        html += "</table><br><br>"

    html += "</body></html>"
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)

# ═══════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="CISBenchChecker v1.0 - Hardening Tool")
    parser.add_argument("--ssh", help="Remote target (user@host)", default=None)
    parser.add_argument("--key", help="Path to SSH key for remote target", default=None)
    parser.add_argument("--password", help="SSH Password (not recommended)", default=None)
    parser.add_argument("--service", choices=['ssh', 'nginx', 'apache', 'all'], default='all', help="Service to audit")
    parser.add_argument("--level", choices=['1', '2', 'all'], default='1', help="CIS Level (1, 2 or all)")
    parser.add_argument("--only-fails", action="store_true", help="Show only failed checks")
    parser.add_argument("--export", choices=['json', 'csv', 'html', 'all'], default=None, help="Export format")
    parser.add_argument("--verbose", action="store_true", help="Show full fix hints in terminal")
    parser.add_argument("--quiet", action="store_true", help="Hide banner and minimal output")

    args = parser.parse_args()
    console = Console(quiet=args.quiet)

    if not args.quiet:
        console.print(Panel(r"""[bold cyan]
  ╔══════════════════════════════════╗
  ║       CISBenchChecker v1.0       ║
  ║     SSH · Nginx · Apache         ║
  ╚══════════════════════════════════╝[/bold cyan]""", expand=False, border_style="cyan"))

    executor = RemoteExecutor(args.ssh, args.key, args.password) if args.ssh else LocalExecutor()
    services = ['ssh', 'nginx', 'apache'] if args.service == 'all' else [args.service]
    lvl = 0 if args.level == 'all' else int(args.level)

    audit = run_audit(executor, services, lvl, console)

    if not args.quiet:
        print_terminal_report(audit, console, args.only_fails, args.verbose)

    has_fails = any(res.failed > 0 for res in audit.services.values())

    if args.export:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = f"reports/cisbench_{timestamp}"
        if args.export in ['json', 'all']:
            export_json(audit, f"{base_path}.json")
            console.print(f"[green]Exported: {base_path}.json[/green]")
        if args.export in ['csv', 'all']:
            export_csv(audit, f"{base_path}.csv")
            console.print(f"[green]Exported: {base_path}.csv[/green]")
        if args.export in ['html', 'all']:
            export_html(audit, f"{base_path}.html")
            console.print(f"[green]Exported: {base_path}.html[/green]")

    if has_fails:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
