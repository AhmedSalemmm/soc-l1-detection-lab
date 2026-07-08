# L1 Triage Playbooks

One playbook per alert scenario. Each follows the same six sections: initial questions, evidence to collect, triage steps, false positive indicators, escalation criteria, and closure notes. The shared structure is deliberate: under queue pressure, a fixed shape is what keeps triage consistent between analysts and between the first alert of a shift and the fortieth.

| Playbook | Scenario | Related detection | Sample data |
|---|---|---|---|
| brute-force-login.md | Password guessing and spraying | failed-login-spike, credential-attack-pattern | windows-events, auth-events |
| suspicious-powershell.md | Encoded and download-style PowerShell | suspicious-powershell-command | sysmon-events |
| phishing-alert.md | Reported or gateway-detected phishing | suspicious-process-execution (post-click) | sysmon-events |
| malware-edr-alert.md | AV/EDR detections | new-service-creation (persistence follow-up) | sysmon-events, windows-events |
| port-scan.md | Internal or external scanning | port-scan-indicators | firewall-events |
| impossible-travel.md | Geographically impossible or unusual logins | manual exercise, no automated rule | auth-events |
| data-exfiltration.md | Large or unusual outbound transfers | manual exercise, no automated rule | firewall-events |

To practice: pick a planted scenario from `sample-logs/README.md`, run the parser or grep the logs yourself, and work the matching playbook end to end, finishing with a filled `docs/incident-report-template.md`. The example report in `reports/` shows the expected depth.
