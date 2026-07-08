# Daily SOC Report Template

End-of-shift summary. The goal is a clean handoff: the next shift should know what is open, what is watched, and what changed, in under two minutes of reading.

---

## Daily SOC Report

| Field | Value |
|---|---|
| Date | |
| Shift | |
| Analyst | |

### Alert volume

| Metric | Count |
|---|---|
| Alerts received | |
| Closed as FP | |
| Closed as BTP | |
| True positives | |
| Escalated | |
| Still open at handoff | |

### Escalations

| Ticket | Severity | One-line summary | Handed to |
|---|---|---|---|

### Open items for next shift

What is unresolved, what to watch, and any timers running (for example: "watching 10.0.20.45 for renewed 4625 activity until 08:00 UTC").

### Notable but closed

Anything closed that the next shift should still know about: unusual BTPs, near-misses, patterns forming across days.

### Tuning candidates

| Rule | Problem | Suggested change |
|---|---|---|

### Environment notes

Maintenance windows, known outages, scanner schedules, or anything that will explain tomorrow's weird-looking alerts.
