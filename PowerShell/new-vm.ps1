#Requires -RunAsAdministrator
param(
    [string]$BaseVHD,
    [string[]]$VMNames,
    [long]$Memory = 4096MB
)

if(-not (Test-Path $BaseVHD)) {
    Write-Error "Failed to find base VHD $BaseVHD"
    return
}

$VMSwitch = Get-VMSwitch -Name "Default Switch" -ErrorAction Stop
foreach($VMName in $VMNames) {
    Write-Host "Making new VHD $VMName"
    Copy-Item $BaseVHD "..\$VMName`.vhdx" -ErrorAction Stop
    Write-Host "Creating new VM $VMName"
    $VM = New-VM -Name $VMName -MemoryStartupBytes $Memory -NoVHD -Generation 2 -SwitchName $VMSwitch.Name -ErrorAction Stop
    Set-VMProcessor -VM $VM -Count 2
    Add-VMHardDiskDrive -VM $VM -Path "..\$VMName`.vhdx"
    Set-VMFirmware -VM $VM -EnableSecureBoot Off
    # Get the disk and network adapter objects
    $disk = Get-VMHardDiskDrive -VM $VM
    $nic = Get-VMNetworkAdapter -VM $VM

    # Set the boot order to boot from the disk first
    Set-VMFirmware -VM $VM -BootOrder $disk,$nic
}