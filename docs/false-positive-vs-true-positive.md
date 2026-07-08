# False Positive vs True Positive: Worked Examples

Classification definitions are in `alert-classification-guide.md`. This document walks through paired examples using the same alert types as the rules in `detections/`, because the difference between FP and TP is almost never in the alert itself. It is in the surrounding evidence.

## Example 1: Failed login spike

**Alert:** 15 failed logons (event 4625) for account `svc-backup` from 10.0.20.45 in 3 minutes.

**Turned out FP:** 10.0.20.45 is the backup server. The service account password was rotated the previous evening and the backup job was still using the cached old password. Failures happen exactly every 30 seconds (a retry loop, not a human or a wordlist), stop after the job window, and there are no attempts against any other account. Verdict: FP, ticket to the backup owner to update the credential.

**Turned out TP:** the same alert, but the source is a workstation in a different subnet that has no business talking to this server, failures come at irregular sub-second intervals, the same source also touched `administrator` and `sqlsvc`, and there is a successful logon (4624, logon type 3) at the end. Verdict: TP, escalate immediately with the success highlighted.

**What made the difference:** source system role, retry cadence, single account vs multiple, and whether a success followed.

## Example 2: Encoded PowerShell

**Alert:** Sysmon event 1, `powershell.exe -NoProfile -EncodedCommand <base64>` on host FIN-WS-07.

**Turned out FP/BTP:** decoding the command shows a known configuration management step; the parent is the endpoint management agent, the same command runs on 200 hosts every Tuesday, and the hash of the parent binary matches the deployed tool. Verdict: BTP, reference the tooling inventory, propose a scoped exclusion for that parent process.

**Turned out TP:** decoding shows a download-and-execute one-liner pointing at an external IP, the parent is `WINWORD.EXE`, and the user opened an email attachment minutes earlier. Verdict: TP, escalate as suspected phishing-delivered execution.

**What made the difference:** the decoded content, the parent process, and prevalence (200 hosts on schedule vs one host once).

## Example 3: Port scan

**Alert:** one source touched 25 ports on one host in 40 seconds.

**Turned out BTP:** source is 192.168.56.5, the vulnerability scanner appliance, and the scan window matches the monthly schedule. Verdict: BTP, reference the scan calendar.

**Turned out TP:** source is a receptionist workstation, the scan runs at 02:00 local time, and the same source then made an RDP connection to the one host that answered. Verdict: TP, escalate; a workstation performing discovery then connecting is not normal behavior for that asset.

**What made the difference:** who the source is supposed to be, timing, and what happened after the scan.

## The general pattern

Across all three examples the deciding evidence was never the alert content. It was:

1. **Identity of the source:** is this system or account supposed to do this?
2. **Cadence:** machine-regular retries vs human or tool-driven irregularity.
3. **Blast radius:** one target or account vs many.
4. **What happened next:** an alert followed by success or lateral movement is a different situation than one followed by silence.
5. **Prevalence:** activity seen across the fleet on a schedule is usually tooling; activity unique to one host is worth attention.

If the ticket does not answer these five, the classification is a guess.
