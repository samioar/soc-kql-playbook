Investigate suspicious IP addresses, beaconing behaviour, or unusual outbound connections.

Query: device network activity

DeviceNetworkEvents
| where DeviceName contains "HOSTNAME"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by TimeGenerated desc

This identifies which process on the device initiated the connection.

---

Query: connection spike detection

DeviceNetworkEvents
| summarize Connections=count() by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
| sort by Connections desc

Large spikes in outbound connections may indicate scanning, beaconing, or compromised IoT devices.

---

Query: investigate suspicious IP across logs

union SigninLogs, OfficeActivity, DeviceNetworkEvents
| where IPAddress == "IP_ADDRESS" or ClientIP == "IP_ADDRESS" or RemoteIP == "IP_ADDRESS"
| project TimeGenerated, IPAddress, ClientIP, RemoteIP, UserPrincipalName, DeviceName
| sort by TimeGenerated desc

This checks if the same IP appears across authentication, device, or cloud activity.