# Detection tests

Adversary techniques run deliberately against the lab to validate that the
detection pipeline (host → Wazuh agent → manager → dashboard) catches them,
correlates them, and maps them to MITRE ATT&CK. Each entry links to a full
report with the commands run, what fired, and captured evidence.

This is distinct from [`../docs/incident-log.md`](../docs/incident-log.md), which
records things that broke and how they were fixed. Here, everything is run
on purpose.

## Tests

| Date | Technique | MITRE | Target | Result | Report |
|------|-----------|-------|--------|--------|--------|
| 2026-10-13 | SSH brute force | T1110 | Rocky | Detected: rule 5712 (level 10) brute-force correlation fired on 5710 invalid-user events | [report](2026-10-13-ssh-bruteforce-t1110.md) |

## Planned

- Credential dumping via Atomic Red Team — T1003
- AI red-teaming of Hermes with NVIDIA Garak
- (add as scoped)

---

### Adding a test

1. Write the report as `YYYY-MM-DD-<short-name>-<technique-id>.md`.
2. Add one row to the table above (newest at the top).
3. If it was planned, remove it from the Planned list.

Report sections to keep consistent: **Objective · Environment · What was
run · What detected · Findings · Evidence captured.**
