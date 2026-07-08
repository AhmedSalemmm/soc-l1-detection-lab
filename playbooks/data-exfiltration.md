# Playbook: Data Exfiltration Suspicion

Large or unusual outbound transfers, uploads to unsanctioned destinations, or data movement that does not fit the host's role. In the sample logs: 10.0.30.66 pushing about 1.8 GB to an external address at 02:41 after a scan and an RDP session.

MITRE: T1048 (Exfiltration Over Alternative Protocol), T1567 if to a web service.

## Initial questions

- How much data, to where, and is that destination categorized (cloud storage, backup provider, unknown host)?
- Does this host or user move data as part of its role (backups, media, CI systems)?
- Is the volume anomalous against this host's own history, not just in absolute terms?
- What happened on the host before the transfer?

## Evidence to collect

- The flow records: destination, port, protocol, byte counts, duration, start time.
- Destination context: ownership, category, reputation, whether anything else in the environment talks to it.
- The host's outbound volume history for a baseline comparison.
- Endpoint context around transfer start: which process made the connection (Sysmon event 3), file access or archive creation shortly before.
- The preceding hours in general: in the sample data the transfer is the third act after a scan and an RDP session, and that sequence is the finding.

## Triage steps

1. Quantify the anomaly: this transfer vs the host's daily norm. 1.8 GB from a build server is noise; from a workstation at 02:41 it is not.
2. Identify the destination. Sanctioned corporate cloud storage changes the ticket to a policy question; an unknown host on a bare IP does not.
3. Tie the transfer to a process if endpoint logs allow it. Browser upload, sync client, and PowerShell socket are three different verdicts.
4. Look for staging behavior before the transfer: archive creation, mass file reads, database dumps.
5. Reconstruct the timeline for the full day on this host. Correlate with any other alerts involving it.
6. Do not block or isolate at L1, but say clearly in the escalation whether the transfer looks complete or ongoing, because that decides how fast containment has to move.

## False positive indicators

- Scheduled backup jobs, offsite replication, or cloud sync clients on their normal cadence and destination.
- OS or application updates being downloaded (direction matters: check whether the volume is actually outbound).
- A user legitimately uploading large media to a sanctioned service, matching their working hours and role.

## Escalation criteria

- Unknown or uncategorized destination with significant outbound volume.
- Transfer preceded by other suspicious activity on the same host (discovery, new services, odd logons).
- Staging indicators: archives created then transferred, mass file access.
- Ongoing transfer at triage time: escalate immediately with the flow details, since every minute is data.

## Closure notes

Record destination, volume, process if identified, baseline comparison, and the preceding timeline. For benign sync and backup traffic, note the destination and cadence so the detection baseline can absorb it instead of re-alerting weekly.
