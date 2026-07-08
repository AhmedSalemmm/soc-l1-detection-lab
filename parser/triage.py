#!/usr/bin/env python3
"""Run the lab detection rules against the synthetic logs and write an alert summary.

This is a teaching tool, not a SIEM. It applies the same logic as the Sigma
rules in detections/ to the JSONL files in sample-logs/, prints the resulting
alerts, and writes a markdown summary an analyst could triage from.

Usage:
    python parser/triage.py
    python parser/triage.py --logs sample-logs --out output

Requires Python 3.11+ (no third-party packages).
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Mirrors the thresholds in detections/. Lab-sized values; production needs tuning.
FAILED_LOGON_THRESHOLD = 6
FAILED_LOGON_WINDOW = timedelta(minutes=2)
SPRAY_USER_THRESHOLD = 5
SPRAY_WINDOW = timedelta(minutes=10)
SCAN_PORT_THRESHOLD = 10
SCAN_WINDOW = timedelta(minutes=1)

POWERSHELL_IMAGES = ("\\powershell.exe", "\\pwsh.exe")
POWERSHELL_INDICATORS = (
    "-enc ", "-encodedcommand", "downloadstring", "downloadfile",
    "frombase64string", "iex (", "invoke-expression",
)
OFFICE_PARENTS = ("\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe")
SHELL_CHILDREN = (
    "\\cmd.exe", "\\powershell.exe", "\\pwsh.exe",
    "\\wscript.exe", "\\cscript.exe", "\\mshta.exe",
)
SCRIPTING_IMAGES = SHELL_CHILDREN + ("\\rundll32.exe", "\\regsvr32.exe")
SUSPICIOUS_SERVICE_PATHS = ("\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\")
COMMON_OUTBOUND_PORTS = {80, 443, 53, 8080}

MITRE = {
    "failed-login-spike": ("Credential Access", "T1110.001"),
    "credential-attack-pattern": ("Credential Access", "T1110.003"),
    "suspicious-powershell-command": ("Execution", "T1059.001"),
    "suspicious-process-execution": ("Execution", "T1204.002"),
    "new-service-creation": ("Persistence", "T1543.003"),
    "port-scan-indicators": ("Discovery", "T1046"),
    "unusual-outbound-connection": ("Command and Control", "T1571"),
}

PLAYBOOKS = {
    "failed-login-spike": "playbooks/brute-force-login.md",
    "credential-attack-pattern": "playbooks/brute-force-login.md",
    "suspicious-powershell-command": "playbooks/suspicious-powershell.md",
    "suspicious-process-execution": "playbooks/suspicious-powershell.md",
    "new-service-creation": "playbooks/malware-edr-alert.md",
    "port-scan-indicators": "playbooks/port-scan.md",
    "unusual-outbound-connection": "playbooks/data-exfiltration.md",
}


def load_jsonl(path):
    events = []
    with open(path, encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"warning: skipping malformed line {line_no} in {path}", file=sys.stderr)
                continue
            event["_time"] = datetime.fromisoformat(event["timestamp"])
            events.append(event)
    events.sort(key=lambda e: e["_time"])
    return events


def make_alert(rule, severity, title, entity, events, note=""):
    tactic, technique = MITRE[rule]
    return {
        "rule": rule,
        "severity": severity,
        "title": title,
        "entity": entity,
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "event_count": len(events),
        "tactic": tactic,
        "technique": technique,
        "playbook": PLAYBOOKS[rule],
        "note": note,
        "events": events,
    }


def bursts(items, window, threshold, distinct_key=None):
    """Find non-overlapping time windows where enough events (or enough distinct
    values of distinct_key) occur. Returns lists of events, one per burst.

    A plain sliding window would emit one alert per event once a burst starts.
    Collapsing each burst into a single alert is what a correlation rule does,
    and it is what keeps the output triageable.
    """
    found = []
    i = 0
    while i < len(items):
        j = i
        while j + 1 < len(items) and items[j + 1]["_time"] - items[i]["_time"] <= window:
            j += 1
        burst = items[i : j + 1]
        if distinct_key:
            hit = len({e.get(distinct_key) for e in burst}) >= threshold
        else:
            hit = len(burst) >= threshold
        if hit:
            found.append(burst)
            i = j + 1
        else:
            i += 1
    return found


def detect_failed_login_spike(windows_events):
    alerts = []
    failures = defaultdict(list)
    for event in windows_events:
        if event.get("event_id") == 4625 and event.get("src_ip") not in (None, "-", "127.0.0.1", "::1"):
            failures[event["src_ip"]].append(event)

    for src_ip, events in failures.items():
        for burst in bursts(events, FAILED_LOGON_WINDOW, FAILED_LOGON_THRESHOLD):
            targets = sorted({e.get("user", "?") for e in burst})
            severity = "medium"
            note = ""
            # A success from the same source after the failures is the difference
            # between "attempted" and "likely compromised".
            for event in windows_events:
                if (
                    event.get("event_id") == 4624
                    and event.get("src_ip") == src_ip
                    and burst[-1]["_time"] <= event["_time"] <= burst[-1]["_time"] + timedelta(minutes=10)
                ):
                    severity = "critical"
                    note = (
                        f"Successful logon (4624) for '{event.get('user')}' from {src_ip} "
                        f"at {event['timestamp']}, after the failure burst. Treat as likely compromise."
                    )
                    break
            alerts.append(make_alert(
                "failed-login-spike", severity,
                f"{len(burst)} failed logons from {src_ip} in under {int(FAILED_LOGON_WINDOW.total_seconds() // 60)} minutes",
                f"src_ip={src_ip} targets={','.join(targets)}",
                burst, note,
            ))
    return alerts


def detect_password_spray(auth_events):
    alerts = []
    failures = defaultdict(list)
    for event in auth_events:
        if event.get("result") == "failure":
            failures[event["src_ip"]].append(event)

    for src_ip, events in failures.items():
        for burst in bursts(events, SPRAY_WINDOW, SPRAY_USER_THRESHOLD, distinct_key="user"):
            users = sorted({e.get("user", "?") for e in burst})
            alerts.append(make_alert(
                "credential-attack-pattern", "high",
                f"Failures against {len(users)} distinct accounts from {src_ip}",
                f"src_ip={src_ip} users={','.join(users)}",
                burst,
                "One or two attempts per account is the spray signature: it stays under lockout thresholds.",
            ))
    return alerts


def detect_suspicious_powershell(sysmon_events):
    alerts = []
    for event in sysmon_events:
        if event.get("event_id") != 1:
            continue
        image = event.get("image", "").lower()
        cmdline = event.get("command_line", "").lower()
        if image.endswith(POWERSHELL_IMAGES) and any(hit in cmdline for hit in POWERSHELL_INDICATORS):
            matched = [hit.strip() for hit in POWERSHELL_INDICATORS if hit in cmdline]
            alerts.append(make_alert(
                "suspicious-powershell-command", "high",
                f"Suspicious PowerShell on {event.get('host', '?')}",
                f"host={event.get('host', '?')} user={event.get('user', '?')}",
                [event],
                f"Matched indicators: {', '.join(matched)}. Decode the command before classifying.",
            ))
    return alerts


def detect_office_spawning_shell(sysmon_events):
    alerts = []
    for event in sysmon_events:
        if event.get("event_id") != 1:
            continue
        parent = event.get("parent_image", "").lower()
        image = event.get("image", "").lower()
        if parent.endswith(OFFICE_PARENTS) and image.endswith(SHELL_CHILDREN):
            alerts.append(make_alert(
                "suspicious-process-execution", "high",
                f"{Path(parent).name} spawned {Path(image).name} on {event.get('host', '?')}",
                f"host={event.get('host', '?')} user={event.get('user', '?')}",
                [event],
                "Office applications do not need command interpreters. Likely macro or exploit payload.",
            ))
    return alerts


def detect_service_from_user_path(windows_events):
    alerts = []
    for event in windows_events:
        if event.get("event_id") != 7045:
            continue
        image_path = event.get("image_path", "").lower()
        if any(fragment in image_path for fragment in SUSPICIOUS_SERVICE_PATHS):
            alerts.append(make_alert(
                "new-service-creation", "high",
                f"Service '{event.get('service_name', '?')}' installed from user-writable path on {event.get('host', '?')}",
                f"host={event.get('host', '?')} image_path={event.get('image_path', '?')}",
                [event],
                "Services run as SYSTEM and survive reboots. Legitimate installs rarely live in user paths.",
            ))
    return alerts


def detect_port_scan(firewall_events):
    alerts = []
    denied = defaultdict(list)
    for event in firewall_events:
        if event.get("action") == "deny":
            denied[event["src_ip"]].append(event)

    for src_ip, events in denied.items():
        for burst in bursts(events, SCAN_WINDOW, SCAN_PORT_THRESHOLD, distinct_key="dst_port"):
            ports = sorted({e.get("dst_port") for e in burst})
            targets = sorted({e.get("dst_ip", "?") for e in burst})
            alerts.append(make_alert(
                "port-scan-indicators", "medium",
                f"{src_ip} probed {len(ports)} ports on {','.join(targets)} in under a minute",
                f"src_ip={src_ip} ports={','.join(str(p) for p in ports)}",
                burst,
                "Check what answered, and whether the source connected back to it afterwards.",
            ))
    return alerts


def is_private(ip):
    return ip.startswith(("10.", "192.168.", "172.16.", "127."))


def detect_unusual_outbound(sysmon_events):
    alerts = []
    for event in sysmon_events:
        if event.get("event_id") != 3 or not event.get("initiated"):
            continue
        image = event.get("image", "").lower()
        port = event.get("dest_port")
        dest = event.get("dest_ip", "")
        if image.endswith(SCRIPTING_IMAGES) and port not in COMMON_OUTBOUND_PORTS and not is_private(dest):
            alerts.append(make_alert(
                "unusual-outbound-connection", "high",
                f"{Path(image).name} connected out to {dest}:{port} from {event.get('host', '?')}",
                f"host={event.get('host', '?')} dest={dest}:{port}",
                [event],
                "Scripting processes have no business on uncommon external ports. Possible C2 channel.",
            ))
    return alerts


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def render_markdown(alerts, log_dir):
    lines = [
        "# Alert Summary",
        "",
        f"Generated by `parser/triage.py` against `{log_dir}` on {datetime.now().strftime('%Y-%m-%d %H:%M')}.",
        "",
        f"Total alerts: {len(alerts)}",
        "",
        "| # | Severity | Alert | Entity | Technique |",
        "|---|---|---|---|---|",
    ]
    for idx, alert in enumerate(alerts, 1):
        lines.append(
            f"| {idx} | {alert['severity']} | {alert['title']} | {alert['entity']} | {alert['technique']} |"
        )
    lines.append("")

    for idx, alert in enumerate(alerts, 1):
        lines += [
            f"## Alert {idx}: {alert['title']}",
            "",
            f"- Severity: {alert['severity']}",
            f"- Rule: {alert['rule']}",
            f"- MITRE ATT&CK: {alert['tactic']} / {alert['technique']}",
            f"- Window: {alert['first_seen']} to {alert['last_seen']} ({alert['event_count']} events)",
            f"- Playbook: {alert['playbook']}",
        ]
        if alert["note"]:
            lines.append(f"- Note: {alert['note']}")
        lines += ["", "Evidence (first events):", "", "```json"]
        for event in alert["events"][:5]:
            event_copy = {k: v for k, v in event.items() if not k.startswith("_")}
            lines.append(json.dumps(event_copy))
        if alert["event_count"] > 5:
            lines.append(f"... {alert['event_count'] - 5} more events")
        lines += ["```", ""]

    lines += [
        "## Next steps",
        "",
        "Classify each alert (TP / FP / BTP) using docs/alert-classification-guide.md,",
        "work the linked playbook, and write up anything escalated with",
        "docs/incident-report-template.md.",
        "",
    ]
    return "\n".join(lines)


def main():
    cli = argparse.ArgumentParser(description="Apply the lab detection rules to the sample logs.")
    cli.add_argument("--logs", default="sample-logs", help="directory with the JSONL log files")
    cli.add_argument("--out", default="output", help="directory for the markdown alert summary")
    args = cli.parse_args()

    log_dir = Path(args.logs)
    if not log_dir.is_dir():
        sys.exit(f"error: log directory not found: {log_dir}")

    sources = {}
    for name in ("windows-events", "sysmon-events", "firewall-events", "auth-events"):
        path = log_dir / f"{name}.jsonl"
        sources[name] = load_jsonl(path) if path.exists() else []
        if not path.exists():
            print(f"warning: {path} not found, related detections skipped", file=sys.stderr)

    alerts = (
        detect_failed_login_spike(sources["windows-events"])
        + detect_password_spray(sources["auth-events"])
        + detect_suspicious_powershell(sources["sysmon-events"])
        + detect_office_spawning_shell(sources["sysmon-events"])
        + detect_service_from_user_path(sources["windows-events"])
        + detect_port_scan(sources["firewall-events"])
        + detect_unusual_outbound(sources["sysmon-events"])
    )
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a["severity"]], a["first_seen"]))

    total_events = sum(len(events) for events in sources.values())
    print(f"parsed {total_events} events, raised {len(alerts)} alerts\n")
    for idx, alert in enumerate(alerts, 1):
        print(f"[{alert['severity'].upper():8}] {idx:>2}. {alert['title']}")
        print(f"           {alert['entity']}")
        print(f"           {alert['tactic']} / {alert['technique']}  |  {alert['playbook']}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "alert-summary.md"
    out_file.write_text(render_markdown(alerts, log_dir), encoding="utf-8")
    print(f"\nalert summary written to {out_file}")


if __name__ == "__main__":
    main()
