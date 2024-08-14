#Requires -RunAsAdministrator
$Script:UserName = "Will"
function Create-MyUser {
    $password = Read-Host -AsSecureString "Enter Password"
    New-LocalUser -Name $Script:UserName -Password $password -FullName $Script:UserName -Description "Standard User"
    Add-LocalGroupMember -Group "Administrators" -Member $Script:UserName
}

function Create-CoreFolders {
    $Folders = "C:\Tools", "C:\Scratch", "C:\Data", "C:\Public", "C:\Dumps"
    $Folders | ForEach-Object {
        New-Item $_ -ItemType Directory | Out-Null
    }
}

function Download-Software {
    Push-Location "C:\Scratch"
    $Packages = "WiresharkFoundation.Wireshark", "Sysinternals Suite"
    $Packages | ForEach-Object {
        winget install $_ --silent --accept-source-agreements --accept-package-agreements
    }
    Pop-Location
}

function Setup-Software {
    Push-Location "C:\Tools"
    Start-Process "procdump.exe" -ArgumentList "-i -ma 'C:\Dumps'" -Wait
    Start-Process "bcdedit" -ArgumentList "/set testsigning on"
    Set-Processmitigation -Name "c:\windows\system32\lsass.exe" -Disable UserShadowStack
    Pop-Location
}

function Setup-Shares {
    New-SmbShare -Name "Public" -Path "C:\Public" -FullAccess "Everyone"
}

function Setup-SSH {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    # Start the sshd service
    Start-Service sshd

    # OPTIONAL but recommended:
    Set-Service -Name sshd -StartupType 'Automatic'

    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }

    # Perform the replacement
    $ConfigPath = "C:\ProgramData\ssh\sshd_config"
    $fileContent = Get-Content C:\ProgramData\ssh\sshd_config
    $fileContent = $fileContent -replace '^Subsystem\s+sftp\s+sftp-server\.exe$', 'Subsystem   sftp    sftp-server.exe -d "c:\Public"'
    Set-Content $ConfigPath $fileContent


# Write the updated content back to the file
Set-Content -Path $filePath -Value $fileContent

}

function Setup-RDP {
    # Enable Remote Desktop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Script:UserName
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

Write-Host "Creating core user"
Create-MyUser
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
Write-Host "Setting up OpeNSSH"
Setup-SSH
Write-Host "Setup RDP"
Setup-RDP
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