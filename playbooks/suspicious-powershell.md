# Playbook: Suspicious PowerShell

Triggered by `suspicious-powershell-command.yml`: encoded commands, hidden windows, download-and-execute patterns.

MITRE: T1059.001, often with T1027 (obfuscation).

## Initial questions

- What does the command actually do? Decode it before judging it.
- What is the parent process? PowerShell from an admin console and PowerShell from Word are different situations.
- Who is the user, and do they or their tooling normally run PowerShell?
- Did the process do anything after starting: network connections, file writes, child processes?

## Evidence to collect

- Full command line and, if encoded, the decoded content. Decode base64 locally, never by running it.
- Parent image and the full process chain up to the user action that started it.
- Sysmon event 3 entries for the same process (network connections with destination and port).
- Sysmon events 11 and 13 around the same time (files written, registry changes).
- Whether the same command line appears on other hosts (prevalence).

## Triage steps

1. Decode the encoded command using a local tool (CyberChef offline, or `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))` in a scratch console). Paste the decoded text into the ticket.
2. Classify the decoded intent: output/configuration commands, module loads, or download-and-execute logic pointing at an address.
3. Walk the parent chain. Office application, browser, or archive tool as parent raises severity immediately. Management agent as parent points toward tooling.
4. Check prevalence: the same encoded command on 200 machines on a schedule is deployment tooling; on one machine once, it is not.
5. Check what followed: outbound connections to unfamiliar addresses, dropped executables, new services or scheduled tasks.
6. If the decoded content references an external address, check the firewall logs for whether the connection happened and how much data moved.

## False positive indicators

- Parent process is a known management or deployment agent and the host count is high.
- Decoded content matches documented internal automation.
- Signed scripts from an internal path executed by a service account that always runs them.
- Admin working interactively during business hours with a command that matches their change ticket.

## Escalation criteria

- Decoded content downloads or executes anything from an external address.
- Parent is an Office application, browser, or anything else user-content-driven.
- Followed by outbound connections on unusual ports, new services, or scheduled tasks.
- Obfuscation beyond plain base64 (string concatenation, char casting, compression) even if the final payload is unclear. Effort spent hiding intent is itself a signal.

## Closure notes

Always include the decoded command in the ticket, whatever the verdict. "Closed as FP, encoded command" is not reviewable; "closed as FP, decodes to the weekly inventory script pushed by the management agent, same hash on 214 hosts" is.
