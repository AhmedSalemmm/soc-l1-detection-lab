# Sample Logs

Synthetic log data for practicing triage without a SIEM. Every event is hand-written; nothing here came from a real environment. External IP addresses use the reserved documentation ranges (203.0.113.0/24, 198.51.100.0/24), internal addresses are RFC 1918, and all hostnames and usernames are invented. The one encoded PowerShell command decodes to `Write-Output 'synthetic lab event'`.

The files are JSON Lines: one JSON object per line, simplified field names instead of full Windows XML schemas, timestamps in UTC.

## Files

| File | Simulates | Key fields |
|---|---|---|
| windows-events.jsonl | Windows Security (4624, 4625) and System (7045) events | event_id, host, user, src_ip, logon_type, image_path |
| sysmon-events.jsonl | Sysmon process creation (1) and network connection (3) | image, command_line, parent_image, dest_ip, dest_port |
| firewall-events.jsonl | Perimeter and internal firewall flow logs | src_ip, dst_ip, dst_port, action, bytes_out |
| auth-events.jsonl | VPN and cloud authentication events | user, src_ip, geo, result |

## What is hidden in the data

The logs cover 2026-06-22 and 2026-06-23 and contain both routine activity and five planted scenarios. Try triaging them yourself before reading further or running the parser.

1. **Brute force with a success** (windows-events): an external source works through passwords for a privileged account on SRV-FS01 at 02:14 and gets in. This is the scenario behind the example incident report in `reports/`.
2. **Phishing execution chain** (sysmon-events plus windows-events): on FIN-WS-07, Outlook spawns Word on a macro-enabled attachment, Word spawns hidden encoded PowerShell, PowerShell connects out on port 8443, and two minutes later a service installs from `C:\Users\Public\`. Four detections fire on one chain.
3. **Password spray** (auth-events): one external IP quietly fails against seven different VPN accounts at 03:10, one attempt each.
4. **Night-time scan then RDP then large upload** (firewall-events): workstation 10.0.30.66 sweeps 15 ports on 10.0.10.5 at 02:03, finds RDP open, connects, and 36 minutes later pushes about 1.8 GB to an external address. The scan alerts automatically; spotting the upload is a manual exercise.
5. **Impossible travel** (auth-events): msamir logs in from Cairo at 09:02 and Amsterdam at 09:41. No automated rule covers this in the lab; it is a manual exercise paired with the impossible-travel playbook.

## Planted false positives

Not everything suspicious-looking is malicious, which is the point of the lab:

- **svc-backup failures** (windows-events, 21:00): seven failures at exactly 20-second intervals with reason "password expired." A retry loop after a password rotation, not an attack. The spike rule still fires; triage should close it as FP.
- **Vulnerability scanner** (firewall-events, 11:00): 10.0.10.250 sweeping 10.0.10.20 during the documented scan window. Fires the port scan rule; correct verdict is benign true positive.
- **jdoe morning typos** (windows-events, 08:02): two failures then a success. Should not alert at all; it is there to keep thresholds honest.

## Regenerating or extending

To add scenarios, follow the existing field names and keep external IPs inside the documentation ranges. The parser in `parser/` only depends on the fields listed in the table above.
