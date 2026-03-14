# Tier 1 SOC Investigation Cheatsheet

Fast triage queries used during the **first 5 minutes of an investigation**.  
These queries help answer the core questions:

- Who logged in?
- From where?
- What device activity occurred?
- Has this IP appeared elsewhere?
- Were privileges changed?

---

## 1. User Authentication Timeline

Used when an alert involves a **user account**.

Shows recent login behaviour including location, IP, and device.


SigninLogs
| where UserPrincipalName contains "USER@DOMAIN"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, DeviceDetail, Status
| sort by TimeGenerated desc

Check for

New IP or location

New device / UserAgent

Rapid repeated logins

2. Failed Login / Password Spray Detection

Used when investigating brute force or password spray alerts.

SigninLogs
| where ResultType != 0
| summarize Attempts=count() by IPAddress, bin(TimeGenerated, 5m)
| where Attempts > 10
| sort by Attempts desc

Check for

One IP hitting multiple accounts

High volume failures in short time

3. Suspicious IP Pivot

Use this when an alert contains a suspicious IP address.

This query checks authentication, device activity, and cloud logs.

union SigninLogs, OfficeActivity, DeviceNetworkEvents
| where IPAddress == "IP_ADDRESS"
   or ClientIP == "IP_ADDRESS"
   or RemoteIP == "IP_ADDRESS"
| project TimeGenerated, IPAddress, ClientIP, RemoteIP, UserPrincipalName, DeviceName
| sort by TimeGenerated desc

Check for

Multiple users affected

Device communications

Cloud access from same IP

4. Device Process Investigation

Used when investigating endpoint alerts or suspicious processes.

DeviceProcessEvents
| where DeviceName contains "HOSTNAME"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc

Check for

Suspicious parent processes

LOLBins (PowerShell, mshta, rundll32)

Encoded or unusual command lines

5. Device Network Connections

Used when investigating outbound connections or beaconing activity.

DeviceNetworkEvents
| where DeviceName contains "HOSTNAME"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by TimeGenerated desc

Check for

External suspicious IPs

Repeated connections

Process initiating network activity

6. Privilege Escalation / Role Changes

Used when alerts involve admin privilege assignment.

AuditLogs
| where OperationName contains "Add member to role"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
| sort by TimeGenerated desc

Check for

Who granted admin rights

Whether action was automated or manual

7. SharePoint / File Access Investigation

Used for possible data exfiltration alerts.

OfficeActivity
| where Operation in ("FileDownloaded","FileAccessed")
| project TimeGenerated, UserId, ClientIP, SiteUrl, SourceFileName
| sort by TimeGenerated desc

Check for

High volume downloads

Access from unfamiliar IPs