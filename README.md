<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jimmiehardy41/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jimmie-mde-test"
| where InitiatingProcessAccountName == "jhardy41"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-25T14:26:22.0604118Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1146" height="339" alt="image" src="https://github.com/user-attachments/assets/0e7fa823-ff21-4125-932e-79efb37220aa">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "jimmie-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1166" height="130" alt="image" src="https://github.com/user-attachments/assets/aa6f885d-32a2-4fee-be1d-e071f128de58" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jimmie-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine 
| order by Timestamp desc
```
<img width="1067" height="336" alt="image" src="https://github.com/user-attachments/assets/6b0a5a1d-94aa-4266-b6a1-96f276f0f498">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jimmie-mde-test"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName,ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1067" height="296" alt="image" src="https://github.com/user-attachments/assets/d0273f98-1981-4f53-9cda-45820a3ad141">


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

14:26:22 UTC — Tor Browser Installation Initiated
User jhardy41 launched the installer tor-browser-windows-x86_64-portable-14.5.5.exe from the Downloads folder.

The installation was done silently (no windows or prompts) using the **/S** switch.

Shortly After — Files Copied to Desktop
Multiple Tor-related files were observed being copied to the desktop, indicating successful installation.

### 2. Process Execution - TOR Browser Installation

14:29:21 UTC — Tor Browser Opened
The executable tor.exe (part of the Tor browser suite) was launched from the desktop, showing the user actively used the browser.

### 3. Process Execution - TOR Browser Launch & Network Connection - TOR Network

14:29:34 UTC — Network Connection via Tor Established
Tor.exe made a successful connection to remote IP 51.89.242.31 on port 9001 (a known Tor port).


The connection included access to the URL: https://www.btlomlipgn75.com.


Additional similar connections were made around this time.



---

## Summary

User jhardy41 downloaded and silently installed the Tor browser on July 25, 2025. Within minutes, they launched the application and successfully used it to access the Tor network, connecting to at least one external site. Interestingly, a month earlier, the creation of a file titled tor-shopping-list.txt suggests premeditation.

---

## Response Taken

TOR usage was confirmed on endpoint jimmie-hardy-test by the user jhardy41. The device was isolated and the user's direct manager was notified.

---
