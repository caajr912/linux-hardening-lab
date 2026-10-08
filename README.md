# Linux Hardening & Compliance Monitoring Lab

A home lab for hardening a Linux server against NIST 800-53 controls, continuously checking that the hardening stays in place, and documenting what broke along the way.

The goal is to practice the work a security operations team does: enforce a baseline, detect drift from it, collect evidence, and root-cause failures instead of guessing.

## Lab setup

| Machine | Role |
| --- | --- |
| Rocky Linux VM | Hardening target |
| Ubuntu VM | Ansible control node |

Both VMs run in VirtualBox on a Windows host, on an isolated lab network.

## What it does

**1. Hardening (`ansible/`).** An Ansible playbook applies 10 NIST 800-53 controls to the target, covering:

- Access control and least privilege
- Identification and authentication
- Audit logging
- Time synchronization
- Least functionality (disabling unneeded services)
- Patching and updates

**2. Drift detection (`drift/`).** A Python checker verifies each control on the live system and reports whether it still passes. Hardening that silently erodes is a real risk, so the checker treats "configured once" and "still configured" as different things.

**3. Evidence (`evidence/`).** Each run writes timestamped JSON results per control, so there is an audit trail of when a control passed or failed.

**4. Monitoring (`monitoring/`).** Drift results are exposed as Prometheus metrics, so compliance status can be watched over time instead of checked by hand.

## Incident log

Real problems hit while building the lab, each written up with symptoms, investigation, and root cause (see `docs/`). Highlights:

- **IP address conflict.** Connectivity was intermittent. Mismatched TTL values in ping replies revealed that two different machines were answering for the same address.
- **Silently failing hardening task.** Ansible reported success, but the drift checker showed the control was not actually applied. This is exactly the failure mode drift detection exists to catch.
- **Lab network misconfiguration.** VMs could not reach each other until the VirtualBox network setup was diagnosed and corrected.

## Skills practiced

Linux administration and hardening, Ansible, Python, NIST 800-53, compliance evidence, Prometheus monitoring, troubleshooting, and root-cause analysis.

## Roadmap

- Ship logs to Wazuh (open-source SIEM) and write detection rules
- Enrich alerts with threat intelligence (WhisperGraph) for domains and IPs the target contacts
- Map detections to MITRE ATT&CK
