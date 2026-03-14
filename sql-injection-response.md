Investigate SQL injection alerts against web applications or databases.

##Query: detect repeated SQL injection attempts

CommonSecurityLog
| where RequestURL contains "'"
or RequestURL contains "union"
or RequestURL contains "select"
| summarize Attempts=count() by SourceIP, RequestURL, bin(TimeGenerated, 5m)
| sort by Attempts desc

Attackers often attempt injection repeatedly using different payloads.

---

##Query: investigate activity from attacker IP

CommonSecurityLog
| where SourceIP == "ATTACKER_IP"
| project TimeGenerated, SourceIP, RequestURL, DeviceAction
| sort by TimeGenerated desc

This determines whether the attacker attempted multiple endpoints.

##Query: correlate attacker IP across environment

union SigninLogs, DeviceNetworkEvents, CommonSecurityLog
| where IPAddress == "ATTACKER_IP" or RemoteIP == "ATTACKER_IP" or SourceIP == "ATTACKER_IP"
| sort by TimeGenerated desc

This checks whether the IP interacted with authentication systems or internal hosts.

---