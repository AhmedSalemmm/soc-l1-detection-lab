# Playbook: Brute-Force Login Attempt

Triggered by `failed-login-spike.yml` or `credential-attack-pattern.yml`. Covers password guessing against one account and spraying across many.

MITRE: T1110.001 (guessing), T1110.003 (spraying).

## Initial questions

- Did any attempt succeed? This single question decides the urgency of everything else.
- Is the target account privileged, a service account, or a normal user?
- Is the source internal or external, and does it have any legitimate reason to authenticate here?
- One account hammered, or one attempt against many accounts?

## Evidence to collect

- All 4625 events for the source IP: count, target accounts, logon types, failure sub-status.
- Any 4624 from the same source, especially after the failure window.
- Timing pattern between attempts (fixed interval vs irregular).
- Source IP context: asset owner if internal, reputation and geolocation if external.
- Account context: lockout events (4740), recent password changes, whether the owner is active.

## Triage steps

1. Search authentication logs for the source IP over the last 24 hours, not just the alert window.
2. Separate the pattern: single target account means guessing, many accounts with one or two attempts each means spraying.
3. Check for any success from that source. If found, treat as compromised until proven otherwise and go straight to escalation.
4. Check the attempt cadence. Exact fixed intervals suggest an automated retry with stale credentials; irregular bursts suggest a tool or a human.
5. Check whether the failure reason is consistent. "Password expired" on every attempt tells a different story than "bad password."
6. If external source: check whether other perimeter alerts (scans, VPN failures) involve the same IP.

## False positive indicators

- Machine-regular retry cadence (for example every 20 or 30 seconds) with a single service account and a recent password rotation on record.
- Failure reason "password expired" or "account disabled" repeated identically.
- Source is a known application server, backup system, or monitoring host whose credential broke.
- Attempts stop on their own at a job window boundary.

## Escalation criteria

- Any successful logon from the attacking source: escalate immediately, do not wait to finish the ticket.
- Target account is privileged or tier-0, even without a success.
- Spray pattern across 5 or more accounts.
- Source is internal with no explanation: a compromised internal host is an incident, not an alert.

## Closure notes

Record: source, targets, attempt count, time window, pattern (guess vs spray), verdict with the deciding evidence, and any tuning suggestion. For FP retry loops, open a ticket to the system owner; the alert will return every day until the credential is fixed, and the note saves the next analyst the same 20 minutes.
