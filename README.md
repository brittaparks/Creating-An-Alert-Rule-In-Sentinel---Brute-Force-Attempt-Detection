# Creating-Alert-Rule-In-Sentinel - Brute Force Attempt Detection

## Explanation
When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, I defined an alert to trigger when the same entity fails to log into the same VM a given number of times within a certain time period. (i.e. 10 failed logons or more per 5 hours). 

## Part 1: Create Alert Rule (Brute Force Attempt Detection)
Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and Timestamp > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
Next, I created the Schedule Query Rule in: Sentinel → Analytics → Schedule Query Rule

### Analytics Rule Settings:

- **Enable the Rule**
- **Select relevant Mitre ATT&CK Framework Categories based on the query**

  <img width="1414" alt="image" src="https://github.com/user-attachments/assets/ece7827a-1628-415b-b4f3-cbbd04797048">


  
- **Run query every 4 hours**
- **Lookup data for last 5 hours** (can define in query)

  <img width="1414" alt="image" src="https://github.com/user-attachments/assets/62cab507-cd72-4413-90d5-6c2b2796e4c9">



- **Stop running query after alert is generated** == Yes (to conserve resources in the test environment)
- **Configure Entity Mappings** for the Remote IP and DeviceName
  
  <img width="1414" alt="image" src="https://github.com/user-attachments/assets/54a2aa8e-e338-4285-b517-aabffea31355">


- **Automatically create an Incident** if the rule is triggered
- **Group all alerts into a single Incident per 24 hours**
- **Stop running query after alert is generated (24 hours)** (to conserve resources in the test environment)

## Part 2: Trigger Alert to Create Incident

Trigger the rule manually to create an incident. If the necessary logs to trigger the rule don’t exist, create the logs by failing to log into the machine an adequate number of times.

## Part 3: Work Incident

Work the incident to completion and close it out, in accordance with the NIST 800-61: Incident Response Lifecycle.

### Preparation
- **Document roles, responsibilities, and procedures.**
- **Ensure tools, systems, and training are in place.**

### Detection and Analysis
- **Identify and validate the incident.**
- **Observe the incident and assign it to yourself, set the status to Active.**

  <img width="1414" alt="image" src="https://github.com/user-attachments/assets/c21ae64e-510e-4e0e-95da-ad3d536d1327">

  
- **Investigate the Incident by Actions → Investigate** (sometimes takes time for entities to appear).
- **Gather relevant evidence and assess impact.**
- **Observe the different entity mappings and take notes:**

  <img width="1414" alt="image" src="https://github.com/user-attachments/assets/1c257a23-ac51-4c92-95d6-6eedc1faea6c">

  
    - The **Britt - Create Alert Rule (Brute Force Attempt Detection)** incident was triggered from 3 different IP addresses, 2 public and 1 private on our same network, against 3 different hosts.
        - `185.243.96.107` Behelit-threat- 100 logon failures
        - `125.25.89.230` Btest 40 logon failures
        - `10.0.0.136` linux-programmatic-zedd.p2zfvso05mlezjev3ck4vqd3kd3.internal.cloudapp[.]net 38 logon failures


<img width="1414" alt="image" src="https://github.com/user-attachments/assets/e3220f88-4a27-4040-bbe0-e9480f9e20a9">


- **Check to make sure none of the IP addresses attempting to brute force the machine actually logged in.**
    - **0 successful logons** from the aforementioned IP addresses.
      
### Device Logon Event Query
```kql
DeviceLogonEvents
| where RemoteIP in ("185.243.96.107", "125.25.89.230", "10.0.0.136")
| where ActionType == "LogonSuccess"
```
 
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/2c42bd2d-9654-4118-9459-1e4802940948">


### Containment, Eradication, and Recovery

- **Isolate affected systems to prevent further damage**
    - In real life, if this was a serious threat, I would isolate the machine with Microsoft Defender for Endpoint.
- **Conduct an Anti-Virus scan**
    - Identify and remove any malware which may be present.
    - Use alternative tools for detection for any malware which may have gone undetected.
- **Adjust NSG settings**
    - NSG was locked down to prevent RDP attempts from the public internet.
- **Adjust Group Policy settings**
    - Account Lockout Threshold lowered for failed login attempts.
- **Remove the threat and restore systems to normal**
    - Brute force was not successful, so no threats related to this incident.
- **Recommendations made for Corporate policy to require this for all VMs going forward (this can be done with Azure Policy)**

# Post-Incident Activities

**Final Review and Closure**
- **Incident Review**
  - Confirmed that no threats were successful and no further malicious activity was detected
- **Final Report**
  - Documented the incident lifecycle, including steps taken, findings, and recommendations for future prevention
- **Incident Closure**
  - Closed the incident in Microsoft Sentinel as a “True Positive” after resolving the issue and documenting the response
    
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/3aa59cc6-cb54-4678-b845-8ca1a4807170">

- **Documented Findings**
  - Recorded notes within the incident
  - Detailed steps taken during the investigation and response
  
- **Lessons Learned**
  - Discussed how we can imrpove processes moving forward
  - Agreed on and finalized recommendations

- **Evidence Retention**
  - Studied incident characteristics to identify systemic weaknesses and threats, and incident trends

- **Using Collected Incident Data**
  - Retained evidence in accordance with organizational standards and industry regulations



   
---
### 📇 Analyst Contact

**Name**: Britt Parks\
**Contact: linkedin.com/in/brittaparks**\
**Date**: May 4, 2025


