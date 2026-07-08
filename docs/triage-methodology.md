# Triage Methodology

The process I follow for every alert in this lab. The point of a fixed method is consistency: two analysts looking at the same alert should reach the same conclusion, and the ticket should show how they got there.

## The 6 steps

### 1. Read the alert properly

Before touching anything else, extract the basics:

- What rule fired, and what is it designed to catch?
- Which host, which user, which source IP?
- When did it fire, and is it still firing?
- What severity did the SIEM assign, and does that match what I see?

If I cannot answer "what is this rule trying to catch," I read the rule logic first. Triaging an alert without understanding the detection behind it is guessing.

### 2. Establish context

- Is this asset a server, a workstation, a domain controller? Who normally uses it?
- Is the user an admin, a service account, a normal user?
- Was there a change window, patch cycle, or known maintenance at that time?
- Has this exact alert fired before on this host or user? What was the verdict then?

### 3. Pull the surrounding evidence

The alert is one event. The decision comes from what happened around it:

- 15 to 30 minutes of logs before and after, for the same host and user.
- Related log sources: if it is an endpoint alert, check authentication and network logs too.
- For process alerts: parent process, full command line, and what the process did next.
- For authentication alerts: source IP history, failure and success pattern, logon type.

### 4. Decide: true positive, false positive, or benign true positive

Use the definitions in `alert-classification-guide.md`. The practical test I apply: "Would I be comfortable explaining this verdict to an L2 with only the evidence in my ticket?" If not, I need more evidence, not a faster close.

### 5. Act according to the verdict

- **False positive:** close with reasoning and evidence. If it keeps firing, note it as a tuning candidate.
- **Benign true positive:** close, reference the change ticket or the confirmed legitimate activity.
- **True positive or cannot rule it out:** escalate using `escalation-criteria.md`. Containment decisions belong to L2 and above; L1 documents and hands off cleanly.

### 6. Document

Every alert gets a record, even a 2-minute false positive close. Use `incident-report-template.md` for anything escalated, and a short closure note otherwise. Unrecorded work did not happen, and closure notes are what make step 2 possible for the next analyst.

## Timeboxing

If I am 20 to 30 minutes into an alert and still cannot classify it, that is itself a signal: escalate with what I have, clearly marked as "unconfirmed, needs deeper analysis." Sitting on an ambiguous alert is worse than escalating it.

## Habits that prevent bad triage

- Never close on the alert title alone. Titles lie; fields do not.
- Check the raw log, not just the SIEM's normalized summary.
- Absence of more alerts is not evidence of absence. One alert can be the only visible part of a chain.
- Write the verdict reason in the ticket, not "FP" with no context.
