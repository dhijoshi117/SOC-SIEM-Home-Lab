# SOC Investigation 09 — Windows Service Installation

## 1. Investigation Summary

**Incident Type:** Windows Service Creation / Potential Persistence

**Classification:** True Positive — Authorized Security Simulation

**Affected Endpoint:** SOC-Windows11-Monitor

**SIEM:** Wazuh 4.14.9

**Severity:** Level 8 (Custom Detection)

**MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service

**Status:** Detection Confirmed; Test Service Cleanup Pending

## 2. Objective

Simulate Windows service installation and investigate the resulting security telemetry using Windows Event Logs and Wazuh SIEM.

The objective was to validate existing detection capabilities and develop a custom Wazuh rule for identifying a specifically named test service.

## 3. Simulation Details

A Windows service was registered through an elevated PowerShell session using the Service Control utility.

**Command executed:**

```powershell
sc.exe create SOC-Lab10-Test binPath= "C:\Windows\System32\cmd.exe" start= demand DisplayName= "SOC Lab 10 Test Service"
```

**Service configuration:**

- Internal service name: SOC-Lab10-Test
- Display name: SOC Lab 10 Test Service
- Executable: C:\Windows\System32\cmd.exe
- Startup type: Manual (Demand Start)
- Service account: LocalSystem

The service was registered but not started. No malicious payload was executed.

## 4. Windows Event Log Analysis

**Security Event ID 4697**

Windows recorded the installation of the test service, including the account responsible, service name, executable path, startup configuration, and service account.

**System Event ID 7045**

Windows Service Control Manager independently recorded the service installation.

Both events confirmed that the simulated activity generated relevant host telemetry.

## 5. Wazuh Detection Analysis

The initial service installation generated an alert using the existing Wazuh rule:

- Rule ID: 61138
- Description: New Windows Service Created
- Severity: Level 5
- Event ID: 7045

A custom rule was subsequently created to match the test service display name and increase alert severity for this controlled simulation.

**Custom detection rule:**

```xml
<rule id="100104" level="8">
  <if_sid>61138</if_sid>
  <field name="win.eventdata.serviceName" type="pcre2">(?i)^SOC Lab 10 Test Service$</field>
  <description>SOC Lab 10: Test Windows service installation detected</description>
  <mitre>
    <id>T1543.003</id>
  </mitre>
  <group>soc_lab,windows_service,persistence,</group>
</rule>
```

The Wazuh configuration passed validation using `wazuh-analysisd -t`, and the manager was restarted.

Following service deletion and recreation, custom Rule 100104 successfully generated a Level 8 alert.

## 6. Evidence

**Dashboard screenshot:** `lab10-windows-service-installation-alert.png`

**Confirmed alert details:**

- Rule ID: 100104
- Severity: Level 8
- Agent: SOC-Windows11-Monitor
- Description: SOC Lab 10: Test Windows service installation detected
- Matching dashboard events: 1

The alert confirms successful collection and detection of the simulated service-installation activity.

## 7. Findings and Assessment

**Finding 1:** Windows Security Event 4697 and System Event 7045 provided complementary service-installation evidence.

**Finding 2:** Wazuh's built-in Rule 61138 detected the service installation without additional customization.

**Finding 3:** Custom Rule 100104 successfully identified the specifically named test service and generated a Level 8 alert.

**Finding 4:** The service was configured to run under LocalSystem, a highly privileged account, but was not started.

**Assessment:** The detection was a true positive for the authorized test activity. No evidence of malicious execution or unauthorized persistence was identified.

The custom rule is intentionally specific to the lab service name and should not be represented as a general-purpose malicious-service detection.

## 8. Recommendations

- Monitor Windows Security Event 4697 and System Event 7045 for unexpected service installations.
- Investigate unfamiliar service names, executable paths, startup configurations, and privileged service accounts.
- Correlate service-installation events with process creation and other endpoint telemetry.
- Develop broader production detections using suspicious executable locations, unexpected parent processes, and environment-specific baselines.
- Remove authorized test services after validation.

## 9. Conclusion

This investigation demonstrated successful Windows service-installation monitoring, SIEM alert analysis, custom Wazuh rule development, and detection validation.

The simulation was authorized and benign. The custom rule successfully detected the intended activity, demonstrating practical SOC monitoring and detection engineering skills.
