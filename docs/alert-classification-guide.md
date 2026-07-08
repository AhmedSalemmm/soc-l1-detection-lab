# Alert Classification Guide

How alerts get classified in this lab. Consistent classification matters because these labels drive tuning decisions, metrics, and whether an incident gets attention.

## Classifications

### True Positive (TP)

The detection fired and the activity is genuinely malicious or unauthorized. Example: 40 failed logons across 12 accounts from one external IP in 5 minutes, followed by a success on an account whose owner is on leave.

Action: escalate per `escalation-criteria.md`. Never close a TP at L1.

### False Positive (FP)

The detection fired but the activity it matched is not what the rule intends to catch. The rule logic matched, the threat did not. Example: a brute-force rule firing on a misconfigured application retrying a bad stored password every 30 seconds.

Action: close with evidence and reasoning. Recurrent FPs go on the tuning list with the rule name, the matched condition, and a suggested exclusion.

### Benign True Positive (BTP)

The detection fired, the activity is exactly what the rule looks for, but it is authorized. Example: a port scan alert caused by the scheduled vulnerability scanner, or an encoded PowerShell alert caused by a known deployment script.

Action: close, referencing the authorization (change ticket, scan schedule, tooling inventory). If it recurs on a fixed schedule, propose a scoped exclusion, never a blanket one.

### Undetermined

Evidence is insufficient to classify within a reasonable triage window.

Action: escalate marked as undetermined. Do not close alerts as "probably fine."

## Why FP vs BTP is worth distinguishing

Both get closed, but they mean different things:

- Many FPs mean the rule logic is bad and needs rewriting.
- Many BTPs mean the rule logic is good but needs scoping (exclusions for known tools and schedules).

If you log both as "FP," the detection engineer cannot tell whether to fix the rule or scope it.

## Severity assignment

Severity reflects impact and confidence together. In this lab:

| Severity | Meaning | Example |
|---|---|---|
| Critical | Confirmed malicious activity with likely impact | Successful logon after brute force on an admin account |
| High | Strong indicators, impact plausible | Encoded PowerShell downloading from an external IP |
| Medium | Suspicious pattern, needs correlation | Failed login spike with no success |
| Low | Policy or hygiene issue, no active threat indicator | Single port scan from an internal host, no follow-up |

An alert can move up or down in severity during triage. Document the change and why.

## Classification quick reference

| Question | Yes | No |
|---|---|---|
| Did the rule match the kind of activity it was built for? | TP or BTP | FP |
| Is the activity authorized and expected? | BTP | TP |
| Can you prove either answer with evidence? | Classify | Undetermined, escalate |
