#Authentication domain

Used when investigating login alerts, brute force attempts, impossible travel, suspicious IPs, or credential abuse.

Query: user sign-in timeline

SigninLogs
| where UserPrincipalName contains "USER@DOMAIN"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, DeviceDetail, Status
| sort by TimeGenerated desc

What you are checking
Login pattern, IP changes, and device changes. Also compare historical UserAgent behaviour to see if the device is consistent.

---

Query: failed login spray detection

SigninLogs
| where ResultType != 0
| summarize Attempts=count() by IPAddress, bin(TimeGenerated, 5m)
| where Attempts > 10
| sort by Attempts desc

What you are checking
A single IP rapidly attempting authentication across accounts.

---


Query: failures followed by success

SigninLogs
| summarize
Failed=countif(ResultType != 0),
Success=countif(ResultType == 0)
by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where Failed > 5 and Success > 0

What you are checking
Credential stuffing where attackers eventually succeed.

---

#Identity / privilege domain

Used when investigating suspicious role assignments, admin creation, or directory modifications.

Query: admin role assignment

AuditLogs
| where OperationName contains "Add member to role"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
| sort by TimeGenerated desc

What you are checking
Who granted privilege and whether the actor was automation or a real account.

---

Query: user account changes

AuditLogs
| where OperationName contains "Update user"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
| sort by TimeGenerated desc

What you are checking
Attribute changes such as MFA removal or account modifications.

---

Query: full user activity timeline

union SigninLogs, AuditLogs, OfficeActivity
| where UserPrincipalName contains "USER@DOMAIN"
| project TimeGenerated, UserPrincipalName, OperationName, IPAddress
| sort by TimeGenerated desc

This builds a timeline of authentication and actions performed by the account.

---