# Weekly SOC Report Template

Weekly rollup aimed at the SOC lead. Where the daily report is a handoff, the weekly report is about trends: what is getting noisier, what tuning paid off, and where triage time is going.

---

## Weekly SOC Report

| Field | Value |
|---|---|
| Week | (dates) |
| Prepared by | |

### 1. Summary

Three or four sentences: overall alert picture, any real incidents, and the main change from last week.

### 2. Volume and outcomes

| Metric | This week | Last week | Trend |
|---|---|---|---|
| Total alerts | | | |
| False positives | | | |
| Benign true positives | | | |
| True positives | | | |
| Escalations | | | |
| Median time to triage | | | |

### 3. Incidents

One row per escalated incident, linking to the full report.

| Report ID | Severity | Summary | Status |
|---|---|---|---|

### 4. Top noisy rules

| Rule | Fires | FP rate | Action |
|---|---|---|---|

If a rule is above roughly 90 percent FP for two weeks running, it needs a tuning decision, not more triage effort.

### 5. Tuning completed this week

What changed, why, and the observed effect on volume.

### 6. Detection gaps noticed

Activity that should have alerted and did not, or fields that were missing during triage. This feeds detection engineering.

### 7. Next week

Planned tuning, follow-ups on open incidents, and anything the SOC lead needs to decide.
