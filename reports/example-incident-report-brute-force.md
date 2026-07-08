# Example Incident Report

Filled from the brute-force scenario in the sample logs, using `docs/incident-report-template.md`. This is the level of detail I aim for in an L1 escalation.

---

## Incident Report

| Field | Value |
|---|---|
| Report ID | IR-20260622-01 |
| Analyst | A. Salem (L1) |
| Date/time opened (UTC) | 2026-06-22 02:22 |
| Alert source | failed-login-spike (Sigma correlation, 8 events / 2 min threshold) |
| Severity | Critical |
| Classification | True Positive |
| Status | Escalated |
| Escalated to | L2 on-call |

### 1. Summary

An external address (203.0.113.42) performed a password guessing attack against the built-in administrator account on file server SRV-FS01 and succeeded on approximately the ninth attempt. There is a confirmed successful network logon from the attacking address 24 seconds after the last failure. The account should be treated as compromised and the server as accessed by an unauthorized party.

### 2. Timeline (UTC)

| Time | Event | Source |
|---|---|---|
| 02:14:05 | First failed logon (4625), administrator @ SRV-FS01 from 203.0.113.42 | Windows Security |
| 02:14:05 to 02:15:17 | 8 failed logons total, irregular intervals of 6 to 14 seconds | Windows Security |
| 02:15:41 | Successful logon (4624, type 3) administrator from 203.0.113.42 | Windows Security |
| 02:16 | Alert fired | SIEM |
| 02:22 | Triage started | |
| 02:31 | Success from attacking source confirmed, escalated to L2 | |

### 3. Affected assets and accounts

| Item | Type | Role | Impact assessment |
|---|---|---|---|
| SRV-FS01 | Host | File server | Accessed by unauthorized party after 02:15:41 |
| administrator | Account | Built-in local admin | Credentials compromised |

### 4. Evidence

Failure burst (first and last shown, 8 total):

```json
{"timestamp": "2026-06-22T02:14:05Z", "event_id": 4625, "host": "SRV-FS01", "user": "administrator", "src_ip": "203.0.113.42", "logon_type": 3, "failure_reason": "bad password"}
{"timestamp": "2026-06-22T02:15:17Z", "event_id": 4625, "host": "SRV-FS01", "user": "administrator", "src_ip": "203.0.113.42", "logon_type": 3, "failure_reason": "bad password"}
```

Success from the same source:

```json
{"timestamp": "2026-06-22T02:15:41Z", "event_id": 4624, "host": "SRV-FS01", "user": "administrator", "src_ip": "203.0.113.42", "logon_type": 3}
```

### 5. Analysis

The pattern is password guessing, not a spray: all 8 failures target one account, and the intervals are irregular (6 to 14 seconds), unlike the fixed-interval retry loops we see from broken service credentials (compare the svc-backup pattern at 21:00 the same day, which retries at exactly 20-second intervals with reason "password expired").

The source is external and has no business relationship with this host. Ruled out: no change ticket for SRV-FS01 in this window, no VPN session maps to this address, and the address does not appear in the 30-day authentication history for any account.

The deciding evidence is the 4624 at 02:15:41. Without it this would be a medium "attempted" ticket. With it, the working assumption is compromise of a local admin account on a file server, which is why this went to L2 before deeper timeline work.

### 6. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence supporting it |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | 8x 4625, single account, single source, irregular cadence |
| Initial Access | Valid Accounts | T1078 | 4624 from attacking source using the guessed credentials |

### 7. Actions taken

- Collected and preserved the full 4625/4624 event set for the window.
- Checked source address against VPN sessions, change tickets, and 30-day auth history: no matches.
- Escalated to L2 on-call at 02:31 with recommendation below.
- No containment performed at L1.

### 8. Recommended next steps

- Disable or reset the administrator credential on SRV-FS01 and review whether the same password is reused on other hosts.
- Review SRV-FS01 activity after 02:15:41: new processes, services, scheduled tasks, file access, outbound connections.
- Block or monitor 203.0.113.42 at the perimeter per L2 decision.
- Longer term: SRV-FS01 accepts logons for the built-in administrator from external sources, which is itself a finding. Exposure should be reviewed regardless of this incident's outcome.

### 9. Closure notes

Left open at escalation. For the next analyst: the same source should be watched for renewed activity, and the svc-backup alert from 21:00 is unrelated (documented separately as FP, broken credential after rotation).
