# Sysmon Setup Guide

Sysmon (System Monitor) is a free Sysinternals tool that logs detailed endpoint activity to the Windows Event Log: process creation with full command lines, network connections, file creation, registry changes, and more. Default Windows auditing does not give you command lines or process ancestry, and those two fields are where most endpoint triage decisions get made.

## 1. Download

Get Sysmon from the official Sysinternals page:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## 2. Pick a configuration

Do not run Sysmon without a config file. The two community baselines worth knowing:

- SwiftOnSecurity sysmon-config: a sane, well-commented default. Good starting point.
  https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong sysmon-modular: modular, mapped to MITRE ATT&CK per include file. Better once you want to tune.
  https://github.com/olafhartong/sysmon-modular

For this lab I use the SwiftOnSecurity config unmodified.

## 3. Install

PowerShell as Administrator:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify it is running and logging:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

To update the config later:

```powershell
.\Sysmon64.exe -c sysmonconfig-export.xml
```

## 4. Event IDs that matter most for L1

| Event ID | Meaning | Why L1 cares |
|---|---|---|
| 1 | Process creation | Command line, hashes, parent process. The core triage event. |
| 3 | Network connection | Which process talked to which IP and port. |
| 7 | Image loaded | DLL loads, useful for spotting odd modules. |
| 11 | File created | Dropped files, scripts written to temp paths. |
| 13 | Registry value set | Run keys and other persistence locations. |
| 22 | DNS query | Which process resolved which domain. |

The synthetic logs in `sample-logs/sysmon.jsonl` follow a simplified version of the event 1 and event 3 schemas.

## 5. Generate safe test events

- Event 1: run `powershell.exe -NoProfile -Command "Get-Date"` and find the event with its full command line.
- Event 3: open a browser to any site and find the connection event for the browser process.
- Parent-child: open cmd.exe from the Start menu versus from inside another console, and compare the ParentImage field.

## Limitations

- Sysmon is visibility, not prevention. It records activity, it does not block anything.
- Config quality decides log quality. A bad config either floods the log or misses what matters.
- Logs are local until something ships them. In this lab the Wazuh agent forwards the Sysmon channel (see `wazuh-setup-guide.md`).
