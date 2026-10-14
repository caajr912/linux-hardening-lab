# Detection Test — SSH Brute Force (T1110)

**Date:** 2026-10-13, ~22:05 local
**Objective:** Validate the detection pipeline end to end by generating SSH
brute-force traffic against the hardened Rocky host and confirming Wazuh
detects, correlates, and maps it.

## Environment

| Role | Host | Notes |
|------|------|-------|
| Attacker | Ubuntu server | Source of the SSH attempts |
| Target | Rocky (Wazuh agent, `192.168.56.10`) | Generates sshd events, forwards via agent |
| SIEM | Wazuh manager | Receives, correlates, renders dashboard |

Agent confirmed **Active** in the manager before the test.

## What was run

From the Ubuntu attacker, 12 rapid failed login attempts against a
non-existent user:

```bash
for i in $(seq 1 12); do
  sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no \
    -o PubkeyAuthentication=no fakeuser@192.168.56.10 exit
done
```

The attempts were fired in a tight burst (all 12 inside roughly one
30-second window) to cross Wazuh's brute-force correlation threshold, not
just trigger individual failed-login rules.

> Fill in before committing:
> - Auth case: password auth was **[on / off]** on Rocky at test time
>   (`sshd -T | grep -i passwordauth`). This determines whether the events
>   landed as password-failure or invalid-user/preauth events.
> - Throttling: all 12 attempts **[did / did not]** land cleanly. If some
>   were dropped, `MaxAuthTries` / `MaxStartups` / firewalld was throttling
>   — a sign of the hardening working, not a failure.

## What detected

Confirmed in the dashboard:

- **Events count evolution** — sharp vertical climb to 12 in a single
  burst. The shape itself is the brute-force signature; normal logins don't
  produce 12 failures in half a minute.
- **MITRE ATT&CK — Top Tactics:**
  - Credential Access (12) — T1110 Brute Force. The intended result.
  - Lateral Movement (11) — T1021 Remote Services. The same SSH events map
    here too, because an SSH login attempt is both a credential-guessing
    action and a remote-access action. **No actual pivot occurred** — this
    is tactic overlap on the same events, not demonstrated lateral movement.
- **PCI DSS compliance mappings** — the attempts satisfied logging controls
  10.2.4 (failed-access-attempt logging), 10.2.5 (auth-mechanism logging),
  and 10.6.1. Shows the host meets PCI logging requirements, a separate
  framework from MITRE.

Rule IDs observed: **[fill in from alerts — e.g. 5710 invalid user, 5716
auth failure, 5712/5720/5763 brute-force correlation]**. The higher-level
correlation rule firing is the key result — it's what a plain log grep
would not produce.

## Findings

1. Full pipeline validated: attacker → target sshd → agent forward →
   manager correlation → dashboard render.
2. Brute-force correlation rule fired, not just individual failure rules.
3. Events correctly dual-mapped to Credential Access and Lateral Movement;
   understand the overlap, don't overstate it.
4. **Unrelated:** the Vulnerability Detection panel (0 Critical / 1,140
   High) is Wazuh's package-CVE scanner, dominated by kernel CVEs on an
   un-updated VM. Not caused by this test. Separate remediation item:
   patch the kernel / run updates to clear the high-severity backlog.

## Evidence captured

- [ ] Raw `/var/log/secure` lines on Rocky showing the failed attempts
- [ ] Dashboard — Events count evolution spike
- [ ] Expanded alert JSON showing `rule.id`, `rule.level`, `srcip`
      (Ubuntu attacker), and the T1110 tag
- [ ] MITRE Top Tactics panel
- [ ] PCI DSS compliance panel
