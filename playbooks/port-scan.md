# Playbook: Port Scan

Triggered by `port-scan-indicators.yml`: one source touching many ports or hosts in a short window.

MITRE: T1046 (Network Service Discovery).

## Initial questions

- Is the source internal or external? External scanning of exposed interfaces is constant background noise; an internal workstation scanning is not.
- Is the source a known scanner (vulnerability management, asset discovery, monitoring)?
- What answered? Denied probes matter less than the ports that responded.
- Did the source connect back to anything that answered?

## Evidence to collect

- Full flow list for the source over a wider window: targets, ports, allow/deny, timing.
- Source identity: asset inventory entry, owner, normal behavior profile.
- For internal sources: what the machine was doing before the scan (logons, processes if endpoint logs exist).
- Any follow-up connections from the source to responsive ports, and the bytes moved.

## Triage steps

1. Identify the source. If it is in the documented scanner list, verify the scan window matches the schedule and close as BTP.
2. Map the scan shape: one host many ports (vertical), many hosts one port (horizontal, often worm-like or targeting a specific service), or both.
3. Check the timing. Business hours from an admin subnet reads differently than 02:00 from a receptionist workstation.
4. Look at what happened after the scan. A scan followed by an RDP or SMB session to the one host that answered is the pattern that matters; in the sample logs, 10.0.30.66 does exactly this.
5. For external sources hitting the perimeter: confirm nothing exposed answered in a way it should not, note it, and move on unless it is targeted and persistent.

## False positive indicators

- Source is the vulnerability scanner, network monitoring, or asset discovery system on its documented schedule.
- IT staff running an authorized check; verify against a change ticket, not a verbal claim.
- Applications that legitimately sweep (printer discovery, some backup and clustering software) with a fixed, recurring pattern.

## Escalation criteria

- Internal source with no scanning role, especially outside business hours.
- Scan followed by successful connections to discovered services.
- Scan sourced from a host that recently had another alert (the combination outranks either alone).
- Horizontal scan for a single high-value port (445, 3389, 5985) across many hosts.

## Closure notes

Record source, targets, port count, shape, what answered, and any follow-up connections. For recurring authorized scanners, confirm the source is in the scanner allowlist used by the detection so it stops consuming triage time.
