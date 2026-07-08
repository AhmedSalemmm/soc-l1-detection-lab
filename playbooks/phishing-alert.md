# Playbook: Phishing Alert

Covers user-reported phishing and mail gateway alerts. In this lab the scenario appears from the endpoint side: the FIN-WS-07 chain in the sample logs starts with a macro document that arrived by mail.

MITRE: T1566.001 (attachment), T1566.002 (link).

## Initial questions

- Report or gateway alert? A user report means someone already saw it and may have already clicked.
- Did anyone interact: open the attachment, click the link, enter credentials?
- How many recipients got the same or a similar message?
- Is the sender spoofed, a lookalike domain, or a compromised real account?

## Evidence to collect

- Full message headers (authentication results: SPF, DKIM, DMARC; sending infrastructure).
- URLs and attachment names plus hashes. Handle attachments as evidence, never open them.
- Mail gateway search: all recipients of the same sender, subject, or attachment hash.
- For anyone who interacted: endpoint logs (process creation around the open time) and authentication logs (logons after a credential-entry page).
- Proxy or DNS logs for the phishing domain: who else resolved or visited it.

## Triage steps

1. Confirm it is phishing: header authentication failures, mismatched display name and address, urgency language, credential harvesting page or macro attachment. Analyze URLs and files with local or passive tools only.
2. Scope the campaign: search the gateway for every recipient of the same indicators. One report usually means multiple deliveries.
3. Split recipients into: received only, opened or clicked, entered credentials or executed content.
4. For the interacted group, pivot to endpoint and authentication logs. A macro document followed by Office spawning a shell (see `suspicious-process-execution.yml`) turns this from a phishing ticket into an intrusion ticket.
5. Record indicators: sender, subject, URLs, hashes, sending IPs.

## False positive indicators

- Legitimate marketing or notification mail with aggressive wording flagged by a user out of caution. Thank the user anyway; deterring reports is expensive.
- Internal phishing simulation. Check the simulation calendar before triaging deeply.
- Newsletter infrastructure (tracking links, link-wrapping) that pattern-matches badly at the gateway.

## Escalation criteria

- Anyone entered credentials: escalate for forced reset and session revocation, and check for logons from unfamiliar sources afterward.
- Anyone executed an attachment: escalate as suspected endpoint compromise with the process evidence attached.
- Targeted content (executives, finance, spoofed internal senders) even without interaction.
- More than a handful of recipients: campaign response (gateway block, purge, user notice) needs L2 authority.

## Closure notes

Record the campaign scope (delivered / interacted / compromised counts), indicators, and actions requested. If it was a user report, note whether the reporter was told the outcome; closing the loop keeps future reports coming.
