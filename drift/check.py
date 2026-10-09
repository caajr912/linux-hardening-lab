#!/usr/bin/env python3
"""Compliance drift checker for linux-hardening-lab.

Verifies LIVE system state against the hardening baseline. It never trusts
automation output: every check inspects the running system directly.

Outputs:
  - Timestamped JSON evidence -> /var/lib/drift-check/evidence/
  - Prometheus textfile metrics -> /var/lib/node_exporter/textfile_collector/
Exit code is 1 if any check fails.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

EVIDENCE_DIR = "/var/lib/drift-check/evidence"
METRICS_DIR = "/var/lib/node_exporter/textfile_collector"
METRICS_FILE = os.path.join(METRICS_DIR, "compliance.prom")

BANNED_PACKAGES = ["telnet", "telnet-server", "tftp-server", "rsh",
                   "rsh-server", "ypbind", "cockpit"]
ALLOWED_FW_SERVICES = {"ssh"}
ALLOWED_FW_PORTS = {"9100/tcp"}  # node_exporter, opened in the monitoring step
REQUIRED_AUDIT_WATCHES = [
    "-w /etc/passwd -p wa -k identity",
    "-w /etc/group -p wa -k identity",
    "-w /etc/shadow -p wa -k identity",
    "-w /etc/sudoers -p wa -k privilege",
    "-w /etc/ssh/sshd_config -p wa -k sshd_config",
    "-w /usr/bin/sudo -p x -k privileged_exec",
]

results = []


def run(cmd):
    """Run a command and return stripped stdout (or an ERROR string)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"ERROR: {e}"


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError as e:
        return f"ERROR: {e}"


def read_kv(path):
    """Parse 'key = value' lines, ignoring comments and [sections]."""
    values = {}
    for line in read_file(path).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def sshd_effective():
    """Effective sshd config after all drop-ins are merged (sshd -T)."""
    config = {}
    for line in run(["sshd", "-T"]).splitlines():
        key, _, value = line.partition(" ")
        config[key.lower()] = value.strip()
    return config


def int_at_least(value, minimum):
    return value is not None and value.isdigit() and int(value) >= minimum


def record(control, check, expected, actual, passed):
    results.append({
        "control": control,
        "check": check,
        "expected": expected,
        "actual": actual,
        "pass": bool(passed),
    })


def run_checks():
    sshd = sshd_effective()

    # AC-8 System Use Notification
    issue = read_file("/etc/issue.net")
    record("AC-8", "banner_text", "contains 'Authorized use only'",
           issue.splitlines()[0] if issue else "", "Authorized use only" in issue)
    record("AC-8", "ssh_banner_configured", "/etc/issue.net",
           sshd.get("banner"), sshd.get("banner") == "/etc/issue.net")

    # AC-6 Least Privilege
    record("AC-6", "ssh_permit_root_login", "no",
           sshd.get("permitrootlogin"), sshd.get("permitrootlogin") == "no")

    # IA-2 Identification and Authentication
    record("IA-2", "ssh_password_auth", "no",
           sshd.get("passwordauthentication"), sshd.get("passwordauthentication") == "no")
    record("IA-2", "ssh_kbd_interactive_auth", "no",
           sshd.get("kbdinteractiveauthentication"),
           sshd.get("kbdinteractiveauthentication") == "no")
    tries = sshd.get("maxauthtries", "")
    record("IA-2", "ssh_max_auth_tries", "<= 3", tries,
           tries.isdigit() and int(tries) <= 3)

    # IA-5 Authenticator Management
    pw = read_kv("/etc/security/pwquality.conf")
    record("IA-5", "password_min_length", ">= 14", pw.get("minlen"),
           int_at_least(pw.get("minlen"), 14))
    record("IA-5", "password_min_classes", ">= 3", pw.get("minclass"),
           int_at_least(pw.get("minclass"), 3))

    # AC-3 Access Enforcement
    mode = run(["getenforce"])
    record("AC-3", "selinux_enforcing", "Enforcing", mode, mode == "Enforcing")

    # SC-7 Boundary Protection
    state = run(["firewall-cmd", "--state"])
    record("SC-7", "firewalld_running", "running", state, state == "running")
    services = set(run(["firewall-cmd", "--list-services"]).split())
    record("SC-7", "firewall_services_allowlist", sorted(ALLOWED_FW_SERVICES),
           sorted(services), services <= ALLOWED_FW_SERVICES)
    ports = set(run(["firewall-cmd", "--list-ports"]).split())
    record("SC-7", "firewall_ports_allowlist", sorted(ALLOWED_FW_PORTS),
           sorted(ports), ports <= ALLOWED_FW_PORTS)

    # AU-2 / AU-12 Event Logging and Audit Record Generation
    active = run(["systemctl", "is-active", "auditd"])
    record("AU-2", "auditd_active", "active", active, active == "active")
    loaded_rules = run(["auditctl", "-l"]).splitlines()
    for watch in REQUIRED_AUDIT_WATCHES:
        present = watch in loaded_rules
        record("AU-12", f"audit_watch:{watch.split()[1]}", watch,
               "present" if present else "missing", present)

    # AU-8 Time Stamps
    synced = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    record("AU-8", "time_synchronized", "yes", synced, synced == "yes")

    # CM-7 Least Functionality
    for pkg in BANNED_PACKAGES:
        installed = subprocess.run(["rpm", "-q", pkg],
                                   capture_output=True).returncode == 0
        record("CM-7", f"package_absent:{pkg}", "not installed",
               "installed" if installed else "not installed", not installed)
    cad = run(["systemctl", "is-enabled", "ctrl-alt-del.target"])
    record("CM-7", "ctrl_alt_del_masked", "masked", cad, cad == "masked")

    # SI-2 Flaw Remediation
    timer = run(["systemctl", "is-enabled", "dnf-automatic.timer"])
    record("SI-2", "dnf_automatic_timer", "enabled", timer, timer == "enabled")
    auto = read_kv("/etc/dnf/automatic.conf")
    actual = f"upgrade_type={auto.get('upgrade_type')}, apply_updates={auto.get('apply_updates')}"
    record("SI-2", "auto_apply_security_updates",
           "upgrade_type=security, apply_updates=yes", actual,
           auto.get("upgrade_type") == "security" and auto.get("apply_updates") == "yes")


def write_atomic(path, content, mode=0o644):
    """Write via temp file + rename so readers never see a partial file."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def main():
    run_checks()
    now = datetime.now(timezone.utc)
    failed = [r for r in results if not r["pass"]]

    evidence = {
        "host": socket.gethostname(),
        "timestamp": now.isoformat(),
        "baseline": "linux-hardening-lab (NIST 800-53 mapped)",
        "summary": {"total": len(results), "passed": len(results) - len(failed),
                    "failed": len(failed)},
        "results": results,
    }
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    evidence_path = os.path.join(EVIDENCE_DIR, f"drift-{now.strftime('%Y%m%dT%H%M%SZ')}.json")
    write_atomic(evidence_path, json.dumps(evidence, indent=2) + "\n", mode=0o640)

    lines = [
        "# HELP compliance_check_pass 1 if the check passes, 0 if the control has drifted.",
        "# TYPE compliance_check_pass gauge",
    ]
    for r in results:
        lines.append(f'compliance_check_pass{{control="{r["control"]}",check="{r["check"]}"}} {int(r["pass"])}')
    lines += [
        "# HELP compliance_checks_failing Number of failing checks in the last run.",
        "# TYPE compliance_checks_failing gauge",
        f"compliance_checks_failing {len(failed)}",
        "# HELP compliance_last_run_timestamp_seconds Unix time of the last drift check.",
        "# TYPE compliance_last_run_timestamp_seconds gauge",
        f"compliance_last_run_timestamp_seconds {now.timestamp():.0f}",
    ]
    os.makedirs(METRICS_DIR, exist_ok=True)
    write_atomic(METRICS_FILE, "\n".join(lines) + "\n")

    print(f"{evidence['summary']['passed']}/{len(results)} checks passed -> {evidence_path}")
    for r in failed:
        print(f"  DRIFT {r['control']} {r['check']}: expected {r['expected']}, got {r['actual']}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
