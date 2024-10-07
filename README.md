<h1>Incident Response: Brute Force Attempt - Windows</h1>

- <b>This tutorial outlines the configuration </b>

<h2>Environments and Technologies Used</h2>

- <b>Microsoft Azure</b> 
- <b>Microsoft Sentinel</b>
- <b>Log Analytics Workspace</b>
- <b>Description</b>
- <b>Description</b>

<h2>Operating Systems</h2>

- <b>Windows 10</b>

<h2>Configuration Steps</h2>

![image](https://github.com/user-attachments/assets/de4bd798-951d-4e42-a927-490db4542e3d)
- <b>Navigate to Microsoft Sentinel and click a CUSTOM: BRUTE FORCE ATTEMPT WINDOWS incident</b>
- <b>Set Owner: Ryan Justin De Jesus, Status: Active, Severity: Medium</b>
- <b>Click view full details</b>

![image](https://github.com/user-attachments/assets/2baf4cca-b5fa-4a6c-a4fa-aa35fa81c8ed)
- <b>Click activity log and observe the activity log</b>

![image](https://github.com/user-attachments/assets/6815ceef-2e8f-4de3-82e4-fdbf400cb6ef)
- <b>Observe entities and incident timelines</b>

![image](https://github.com/user-attachments/assets/3a85ff09-ccf6-46b4-acc1-d9fc5cadf8fb)
- <b>Click the IP Address and observe the geolocation information</b>

![image](https://github.com/user-attachments/assets/5c364ca4-8677-4523-bd45-3eb7450ea478)
- <b>Click investigation on the bottom left</b>

![image](https://github.com/user-attachments/assets/7d510b8c-b1cb-4d78-adfc-42e99432f910)
- <b>Investigate and determine the scope</b>

![image](https://github.com/user-attachments/assets/01cdfe3e-676a-4407-88e6-c8de99ee2601)
- <b>Click the IP Address and observe the related event</b>
- <b>This specific incident is related to 4 events</b>

![image](https://github.com/user-attachments/assets/1551a905-5d3e-499e-8bcc-9917fd662d31)
- <b>Click one of the related incidents and see all aggregated nodes</b>

![image](https://github.com/user-attachments/assets/13fd41e2-a891-4642-8dd2-1ac43cd45e96)
- <b>More Information is presented in the Log Analytics Workspace from this query:</b>

``` 
let GetIPRelatedAlerts = (v_IP_Address: string) {
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | extend entities = todynamic(Entities)
    | mv-expand entities
    | project-rename entity=entities
    | where entity['Type'] == 'ip' and entity['Address'] =~ v_IP_Address
    | project-away entity
};
GetIPRelatedAlerts(@'85.133.152.48')
```

![image](https://github.com/user-attachments/assets/734e9966-a58c-48dd-b83e-4ef855bdd29e)
- <b>Determine the legitimacy of the Incident (True Positive, False Positive, etc.)</b>

```
SecurityEvent
| where EventID == 4625
| where IpAddress == '85.133.152.48'
```
 
![image](https://github.com/user-attachments/assets/81553fc9-bf23-41a6-9e03-31306d7bf1ad)
- <b>Based on the results, I will conclude this as a False Positive due to the lack of additional indicators. No other malicious indicators (like unusual account privileges, lateral movement, or known malicious activity) are shown in the log, suggesting the alert may have been triggered prematurely without sufficient evidence.</b>
