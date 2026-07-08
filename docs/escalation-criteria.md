# Escalation Criteria

When L1 hands an alert to L2, and how. Escalating too little lets incidents sit; escalating everything buries L2 and teaches them to ignore the queue. These are the rules I use in this lab.

## Escalate immediately (do not finish triage first)

- Confirmed or strongly suspected malicious activity on a domain controller, identity provider, or other tier-0 asset.
- A successful authentication following a brute-force or spray pattern.
- Signs of active hands-on-keyboard activity: interactive sessions, discovery commands, new admin accounts.
- EDR/AV alert that indicates execution was allowed (detected but not blocked).
- Any credible sign of data leaving the environment.
- Ransomware indicators of any kind.

For these, a short handoff now beats a complete report later. Escalate with what you have and keep collecting.

## Escalate after triage

- True positives of any severity that are not in the immediate list.
- Undetermined alerts once the triage timebox (20 to 30 minutes) is spent.
- Repeated medium alerts on the same asset or account within a shift, even if each one alone looks closable.
- Anything requiring containment (isolation, account disable, block requests). L1 recommends, L2+ decides.

## Do not escalate (close with documentation)

- False positives with evidence for why the logic matched.
- Benign true positives with a reference to the authorizing change, schedule, or tool.
- Known recurring tuning candidates already tracked, unless something about this instance differs.

## What a good escalation contains

An escalation is a handoff, not a forward. Mine include:

1. **One-line summary:** what I think is happening and my confidence.
2. **Verdict so far:** TP / undetermined, and severity with reasoning.
3. **Scope:** hosts, accounts, and time range involved so far.
4. **Evidence:** the key raw events (not just alert IDs), timestamps in UTC, and where to find the rest.
5. **What I checked and ruled out:** saves L2 from repeating my steps.
6. **Recommended next action:** even if L2 overrides it, it shows the thinking.

The `incident-report-template.md` covers all six.

## Escalation anti-patterns

- Forwarding the raw alert with "please check."
- Waiting to build a perfect report while an account is actively being brute-forced.
- Escalating without noting what was already ruled out, forcing duplicate work.
- Verbal-only escalation with nothing in the ticket. If the handoff is not written down, ownership is ambiguous.
