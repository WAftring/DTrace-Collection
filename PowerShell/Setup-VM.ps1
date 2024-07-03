#Requires -RunAsAdministrator
function Create-CoreFolders {
    $Folders = "C:\Tools", "C:\Scratch", "C:\Data", "C:\Public", "C:\Dumps"
    $Folders | ForEach-Object {
        New-Item $_ -ItemType Directory | Out-Null
    }
}

function Download-Software {
    Push-Location "C:\Scratch"
    $Links = "https://2.na.dl.wireshark.org/win64/Wireshark-4.2.5-x64.exe", "https://download.sysinternals.com/files/Procdump.zip", "https://download.sysinternals.com/files/ProcessMonitor.zip"
    $ProgressPreference = "SilentlyContinue"
    $Links | ForEach-Object {
        $OutputFile = $_.Split("/")[-1]
        Write-Host "Downloading $_"
        Invoke-WebRequest $_ -OutFile $OutputFile
        if($OutputFile.Contains(".zip")) {
            Expand-Archive $OutputFile .
            Remove-Item *.zip | Out-Null
        }
        Move-Item * C:\Tools\
    }
    Pop-Location
}

function Setup-Software {
    Push-Location "C:\Tools"
    Start-Process ".\procdump.exe" -ArgumentList "-i -ma 'C:\Dumps'" -Wait
    Start-Process ".\Wireshark-4.2.5-x64.exe" -Wait
    Start-Process "bcdedit" -ArgumentList "/set testsigning on"
    Set-Processmitigation -Name "c:\windows\system32\lsass.exe" -Disable UserShadowStack
    Pop-Location
}

function Setup-Shares {
    New-SmbShare -Name "Public" -Path "C:\Public" -FullAccess "Everyone"
}

function Setup-RegistryKeys {    
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f
    reg add HKLM\Software\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f
    reg add HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell /f /v PrereleaseExperience /t REG_DWORD /d 1
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /f /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1
    reg add HKLM\Software\Microsoft\SecurityManager /f /v InternalDevUnlock /t REG_DWORD /d 1
    reg add HKLM\Software\Microsoft\Windows\Dwm /v ForceEffectMode /t REG_DWORD /d 2 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d "32" /f
    reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunasPPL /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpFolder /t REG_EXPAND_SZ /d "c:\dumps" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpType /t REG_DWORD /d 2 /f
}

Write-Host "Setting up basic folder structure"
Create-CoreFolders
Write-Host "Downloading required software"
Download-Software
Write-Host "Setting up software"
Setup-Software
Remove-Item C:\Scratch\*
Write-Host "Setting up registry keys"
Setup-RegistryKeys
Write-Host "Setting up SMB Shares"
Setup-Shares
Write-Host "Creating PS Profile"
New-Item $PROFILE -Force
@"
function e {
        param(`$Location = ".")
        explorer `$Location
}
"@ | Out-File $PROFILE


Read-Host "Press Enter to restart"

Restart-Computer -Force