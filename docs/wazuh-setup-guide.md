# Wazuh Setup Guide

Steps I use to stand up a single-node Wazuh server for this lab. Wazuh is free, has a built-in ruleset mapped to MITRE ATT&CK, and handles Windows Event Log and Sysmon channels out of the box, which makes it a good fit for L1 practice.

Tested with Wazuh 4.x. Check the official docs for the current version: https://documentation.wazuh.com

## 1. Deploy the server

Easiest option is the official OVA in VirtualBox or VMware:

1. Download the Wazuh OVA from the official site.
2. Import it and give it at least 4 GB RAM and 2 vCPUs.
3. Attach it to the same host-only network as the Windows VM.
4. Log in to the dashboard at `https://<server-ip>` with the credentials shown in the appliance console. Change the default password immediately.

Alternative: Docker single-node deployment following the official `wazuh-docker` repository.

## 2. Install the Windows agent

On the Windows VM (PowerShell as Administrator):

```powershell
# Replace the version and server IP with your values
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="192.168.56.10" WAZUH_AGENT_NAME="win-endpoint-01"
NET START WazuhSvc
```

Confirm the agent shows as **Active** under Agents in the dashboard.

## 3. Collect Sysmon events

Install Sysmon first (see `sysmon-setup-guide.md`), then tell the agent to read the Sysmon channel. Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent service:

```powershell
Restart-Service WazuhSvc
```

## 4. Generate test alerts

Safe ways to confirm the pipeline works, all against your own lab VM:

- Type a wrong password at the Windows lock screen 6 or 7 times in a row, then search the dashboard for event 4625 and brute-force rule matches.
- Run a harmless encoded PowerShell command such as `powershell -enc <base64 of Write-Output 'test'>` and look for Sysmon event 1.
- Install and remove a dummy service with `sc create labtest binPath= "C:\Windows\System32\cmd.exe"` then `sc delete labtest`, and look for event 7045.

## 5. Load the custom rules

The Sigma rules in `detections/` describe the detection logic in a portable format. To use the same logic in Wazuh, translate each rule into a custom Wazuh rule under `/var/ossec/etc/rules/local_rules.xml`, or use them as reference when tuning the built-in ruleset. I kept the rules in Sigma format because it is the industry standard for sharing detections and it is not tied to one SIEM.

## Notes and limitations

- Single-node setup, no clustering, no agent groups. Fine for a lab, not a production design.
- The default ruleset is noisy at first. Tuning it is part of the exercise, not a problem.
- Snapshot the VMs after setup so you can reset the lab quickly.
