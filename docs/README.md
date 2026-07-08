# Documentation

Reference material for the lab, grouped by what you are trying to do.

## Build the lab

- [lab-architecture.md](lab-architecture.md): components, network layout, and the two ways to run the lab (full VMs or offline with the sample logs).
- [wazuh-setup-guide.md](wazuh-setup-guide.md): stand up a single-node Wazuh server and enroll a Windows agent.
- [sysmon-setup-guide.md](sysmon-setup-guide.md): install Sysmon with a tuned config and the event IDs that matter for L1.

## Do the triage

- [triage-methodology.md](triage-methodology.md): the six-step process applied to every alert.
- [alert-classification-guide.md](alert-classification-guide.md): TP, FP, benign true positive, and how severity is assigned.
- [false-positive-vs-true-positive.md](false-positive-vs-true-positive.md): worked examples of the same alert going both ways.
- [escalation-criteria.md](escalation-criteria.md): what goes to L2, when, and what a useful handoff contains.

## Report the work

- [incident-report-template.md](incident-report-template.md): for escalated alerts and true positives. Filled example in [../reports](../reports).
- [daily-soc-report-template.md](daily-soc-report-template.md): end-of-shift handoff.
- [weekly-soc-report-template.md](weekly-soc-report-template.md): trend rollup for the SOC lead.

## Map to ATT&CK

- [mitre-attack-mapping.md](mitre-attack-mapping.md): how the detections and playbooks map to tactics and techniques, and the rules I follow to keep the mapping honest.

## Where the rest lives

- Detection rules: [../detections](../detections)
- Triage playbooks: [../playbooks](../playbooks)
- Synthetic logs: [../sample-logs](../sample-logs)
- Parser: [../parser](../parser)
