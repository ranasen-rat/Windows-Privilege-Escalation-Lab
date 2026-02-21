---
https://github.com/user-attachments/assets/5a84626b-5072-4309-aa02-2def50049707
# 🛡 Windows Privilege Escalation Lab Setup Script

A fully automated **Windows 10/11 Privilege Escalation Lab Environment Builder** for red team training, OSCP-style practice, and cybersecurity labs.

This script configures a deliberately vulnerable Windows machine with multiple real-world privilege escalation vectors for hands-on learning.

---

## 🎯 Lab Purpose

This lab is designed for:

* 🔐 Ethical Hacking Practice
* 🧠 Windows Privilege Escalation Training
* 🎓 OSCP / PNPT / Red Team Preparation
* 🏢 Internal Security Training Environments

It automatically deploys common misconfigurations used in real-world exploitation scenarios.

---

## ⚙️ What This Script Configures

### 👤 Low-Privilege User

* Creates user: `User`
* Password: `Password123!`
* Member of local `Users` group

---

### 🛠 Installed Tools (Auto Download)

* Microsoft Sysinternals

  * `accesschk`
  * `autoruns`
  * `procmon`
* Sherlock
* Tater

All tools are placed in:

```
C:\Users\Public\Desktop\Tools
```

---

## 🔥 Vulnerabilities Implemented

### 1️⃣ Weak Service Permissions

* SERVICE_CHANGE_CONFIG abuse
* Writable service binaries
* DLL Hijacking service
* Registry-based service misconfig
* Unquoted Service Path

### 2️⃣ AlwaysInstallElevated

Enabled in:

```
HKLM
HKCU
```

### 3️⃣ Weak File Permissions

* Writable `Program Files` directories
* Writable Startup folder
* Writable Scheduled Task binary location

### 4️⃣ Scheduled Task (Runs as SYSTEM)

```
MyTask2
```

### 5️⃣ Credential Exposure

* Winlogon stored password
* PuTTY saved credentials
* TightVNC encrypted password
* Base64 password in Unattend.xml
* Web.config plaintext password
* McAfee SiteList.xml password

### 6️⃣ Registry Autorun Abuse

HKLM Run key configured

---

## 🧪 Exploitation Scenarios Included

* DLL Hijacking
* Service Binary Replacement
* Unquoted Path Exploitation
* AlwaysInstallElevated MSI abuse
* Credential Harvesting
* Scheduled Task Abuse
* Writable Autorun Exploitation

**Total: 14 Practical Exercises**

---

## 🚀 Usage

### 1️⃣ Requirements

* Windows 10 or 11 VM
* Run as Administrator
* Internet connection (unless using `-SkipDownloads`)

---

### 2️⃣ Run Script

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\WinPrivEscLab.ps1
```

Optional:

```powershell
.\WinPrivEscLab.ps1 -SkipDownloads
```

---

### 3️⃣ After Setup

1. Log off
2. Login as:

```
User
Password123!
```

3. Start enumeration and exploitation.

---

## 🔐 SSL/TLS Download Issues (Lab Still 100% Functional)

Some Windows lab VMs may experience SSL/TLS download errors when pulling tools directly from the internet.

This is common in:

* Older Windows 10 builds
* Hardened VM templates
* Environments without updated root certificates

---

## ✅ Lab Status: Fully Operational

Even if tool downloads fail, the **core lab environment remains completely functional**.

```
✓ User 'User' created
✓ All 5 vulnerable services configured
✓ Weak permissions applied
✓ Registry passwords stored
✓ Config files deployed
✓ AlwaysInstallElevated enabled
✓ Autorun permissions misconfigured
✓ Scheduled task running as SYSTEM
✓ VNC password stored
✓ All 14 exercises ready
```

⚠️ **Important:**
The services, misconfigurations, and credential exposures are the real vulnerabilities — tools are optional.

---

## 🛠 Quick TLS Fix (Run as Administrator)

If you want to manually download the tools:

```powershell
# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Sysinternals downloads
iwr -uri "https://download.sysinternals.com/files/AccessChk.zip" -out "$env:PUBLIC\Desktop\Tools\AccessChk.zip"
iwr -uri "https://download.sysinternals.com/files/Autoruns.zip" -out "$env:PUBLIC\Desktop\Tools\Autoruns.zip"
iwr -uri "https://download.sysinternals.com/files/Procmon.zip" -out "$env:PUBLIC\Desktop\Tools\Procmon.zip"

# PowerUp (modern alternative to Sherlock/Tater)
iwr -uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -out "$env:PUBLIC\Desktop\Tools\PowerUp.ps1"
```

---

## 🧪 Verify Lab (Login as `User`)

After setup:

1️⃣ Log off
2️⃣ Login as:

```
User
Password123!
```

Then test the exercises:

```cmd
REM Verify vulnerable services (Exercise 1–5)
sc querystate dllsvc
sc querystate daclsvc
sc querystate unquotedsvc

REM Check weak file permissions (Exercise 6–8)
icacls "C:\Program Files\File Permissions Service"

REM Check registry credentials (Exercise 9)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

REM Check VNC stored password (Exercise 10)
reg query "HKCU\Software\TightVNC\Server"
```

---

## 🚀 Workshop Ready

✔ No external tools required
✔ All privilege escalation paths active
✔ Safe for offline environments
✔ Perfect for live demos and classroom labs

The lab is fully operational even without downloads.

---

## 🧰 Useful Kali Command (For Payload Testing)

```bash
msfvenom -p windows/exec CMD='net localgroup administrators User /add' -f exe -o shell.exe
```

---

## 📂 Directory Structure

```
C:\Users\Public\Desktop\Tools
 ├── Accesschk
 ├── Autoruns
 ├── Procmon
 ├── Sherlock
 ├── Tater
 ├── vncpwd
 └── Source
```

---

## 🛑 Important Notice

⚠️ This lab intentionally weakens Windows security.
⚠️ Use ONLY inside an isolated virtual machine.
⚠️ Do NOT run on production systems.

This project is strictly for **educational and ethical security research purposes**.

---

## 📌 Recommended Practice Resources

* Offensive Security
* Hack The Box
* TryHackMe

---

## 👨‍💻 Author

Rana Sen
Cyber Security Researcher | Red Team | Windows Exploitation

---

## ⭐ Contribute

Pull requests are welcome.
Suggestions for additional vulnerabilities are appreciated.

---
