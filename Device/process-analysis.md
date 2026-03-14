Investigate suspicious processes, malware behaviour, or abnormal command execution on endpoints.

Query: device process timeline

DeviceProcessEvents
| where DeviceName contains "HOSTNAME"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc

This shows what processes executed on the device and what launched them.

---

Query: suspicious script execution

DeviceProcessEvents
| where FileName in ("powershell.exe","cmd.exe","wscript.exe","cscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated desc

Script engines are often abused by attackers for lateral movement or payload execution.

Query: encoded PowerShell detection

---

DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
| project TimeGenerated, DeviceName, ProcessCommandLine

Encoded PowerShell commands are frequently used in malicious scripts.