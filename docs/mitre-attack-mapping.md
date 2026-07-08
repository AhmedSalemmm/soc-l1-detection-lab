# MITRE ATT&CK Mapping

Mapping of the detections and playbooks in this repo to ATT&CK tactics and techniques. I kept the mappings narrow on purpose: a detection maps to a technique only when the logged behavior is direct evidence of it, not when it is loosely related. Over-mapping makes ATT&CK coverage look better than it is and misleads whoever reads the coverage report.

Framework reference: https://attack.mitre.org (ATT&CK v15 technique IDs).

## Detection rules

| Rule | Tactic | Technique | ID |
|---|---|---|---|
| Failed login spike | Credential Access | Brute Force: Password Guessing | T1110.001 |
| Credential attack pattern (spray) | Credential Access | Brute Force: Password Spraying | T1110.003 |
| Suspicious PowerShell command | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Suspicious PowerShell command (encoded) | Defense Evasion | Obfuscated Files or Information | T1027 |
| Suspicious process execution (Office spawning shell) | Execution | User Execution: Malicious File | T1204.002 |
| New service creation | Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Port scan indicators | Discovery | Network Service Discovery | T1046 |
| Unusual outbound connection | Command and Control | Non-Standard Port | T1571 |

## Playbook scenarios

| Playbook | Primary tactic | Technique(s) |
|---|---|---|
| Brute-force login | Credential Access | T1110.001, T1110.003 |
| Suspicious PowerShell | Execution | T1059.001 |
| Phishing alert | Initial Access | T1566.001 (attachment), T1566.002 (link) |
| Malware / EDR alert | Execution | T1204 plus whatever the EDR verdict indicates |
| Port scan | Discovery | T1046 |
| Impossible travel / unusual login | Initial Access | T1078 (Valid Accounts) |
| Data exfiltration suspicion | Exfiltration | T1048 (Exfiltration Over Alternative Protocol) |

## Notes on how I map

- **One or two techniques per detection.** If a rule seems to map to five techniques, the rule is probably too vague.
- **Map the observed behavior, not the assumed intent.** A port scan alert is evidence of T1046 discovery activity. It is not evidence of T1595 active scanning by an external actor unless the source is external, and it is not evidence of what the attacker plans next.
- **Sub-techniques where the log fields support them.** Event 4625 volume against one account supports password guessing (T1110.001). One failure across many accounts supports spraying (T1110.003). The parent technique alone (T1110) is the honest choice when the pattern is unclear.
- **Tactics come from context.** The same encoded PowerShell command can be Execution when a user triggers it or Defense Evasion viewed through the encoding. The incident report should say which applies to the case at hand.
