# Playbook: Impossible Travel / Unusual Login

Two successful authentications for the same account from locations that cannot be reached in the time between them, or a login from a source that does not fit the account's history. In the sample logs: msamir, Cairo at 09:02 and Amsterdam at 09:41.

MITRE: T1078 (Valid Accounts).

## Initial questions

- Are both logins real interactive sessions, or is one of them a token refresh, mobile sync, or background job?
- Does the account have VPN, proxy, or cloud-relay usage that explains the geography?
- Is either source IP a datacenter or VPN provider rather than a residential ISP?
- What did the suspicious session do after logging in?

## Evidence to collect

- Both authentication events in full: IP, user agent or client app, auth method, MFA result.
- The account's 30-day login history: usual countries, ISPs, devices, and hours.
- IP ownership for both sources (residential, corporate, hosting provider, VPN service).
- Post-login activity for the anomalous session: mailbox rules created, files accessed, MFA changes, mail forwarding.
- Any recent phishing reports or credential alerts involving this user.

## Triage steps

1. Check the client types first. A laptop session in Cairo plus a mobile app token refresh routed through a European cloud region is the single most common benign explanation.
2. Compare both sessions against the account's history. A source seen daily for a year is background; a first-ever country plus a first-ever device is not.
3. Check MFA: which session satisfied it, and how. An MFA-passed session from a new country still matters if the method was a phishable one, or if MFA fatigue prompts show in the log.
4. Examine what the anomalous session did. Mailbox forwarding rules, mass file access, or MFA method changes decide this ticket regardless of geography.
5. If it remains ambiguous, contacting the user through a known-good channel (not email reply) is legitimate L1 evidence gathering: "are you traveling, and did you log in at 09:41 UTC?"

## False positive indicators

- Corporate VPN or SASE egress points make everyone appear in the provider's geography.
- Mobile clients and background sync sessions with stale tokens.
- The user is genuinely traveling and confirms it via a trusted channel.
- Shared service accounts used from multiple sites (a problem, but a different ticket).

## Escalation criteria

- Anomalous session performed sensitive actions: forwarding rules, MFA changes, permission grants, bulk downloads.
- No benign explanation found and the user cannot be reached.
- The account is privileged or has access to sensitive data.
- Same anomalous source appears across multiple accounts (points to a phishing kit or credential dump in use).

## Closure notes

Record both sessions, the deciding evidence (client type, history match, user confirmation), and the post-login review result. If it was VPN or sync noise, note the pattern so the detection can be tuned by ASN or client type instead of raw geography.
