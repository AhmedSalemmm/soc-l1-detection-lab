# Incident Report Template

Used for any alert that gets escalated or classified as a true positive. A filled example is in `reports/example-incident-report-brute-force.md`.

---

## Incident Report

| Field | Value |
|---|---|
| Report ID | IR-YYYYMMDD-NN |
| Analyst | |
| Date/time opened (UTC) | |
| Alert source | (rule name and ID) |
| Severity | Critical / High / Medium / Low |
| Classification | TP / FP / BTP / Undetermined |
| Status | Open / Escalated / Closed |
| Escalated to | |

### 1. Summary

Two or three sentences: what happened, on what, and why it matters. Written so a shift lead can understand it without opening the SIEM.

### 2. Timeline (UTC)

| Time | Event | Source |
|---|---|---|
| | First observed activity | |
| | Alert fired | |
| | Triage started | |
| | Key findings | |
| | Escalation / closure | |

### 3. Affected assets and accounts

| Item | Type | Role | Impact assessment |
|---|---|---|---|
| | host / account / service | | |

### 4. Evidence

Raw log excerpts with source and timestamp. Enough that the verdict can be verified without SIEM access. Redact anything sensitive if the report leaves the SOC.

### 5. Analysis

What the evidence shows, what was ruled out and how, and the reasoning behind the classification. This is the section L2 reads first.

### 6. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence supporting it |
|---|---|---|---|

Only map techniques the evidence actually supports.

### 7. Actions taken

What L1 did: evidence collected, notifications sent, recommendations made. Note explicitly that no containment was performed at L1, or who authorized it if it was.

### 8. Recommended next steps

For L2/IR: what to check or contain. For detection engineering: tuning notes if relevant.

### 9. Closure notes

Filled at close: final classification, root cause if known, and anything the next analyst should know if this fires again.
