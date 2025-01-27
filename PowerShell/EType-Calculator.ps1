param(
    [int]$SourceSET = 0x1c,
    [int]$TargetSET = 0x1c,
    [int]$KdcSET = 0x1c,
    [switch]$Subsession,
    [switch]$TGT,
    [switch]$DFL
)

$script:KrbtgtSET = 0x18
$script:DomainSET = 0x1c
$script:AesSha2Bits = 0xc0;

class EncryptionType {
    [string]$Name
    [int]$Value
    EncryptionType([string]$name, [int]$value) {
        $this.Name = $name
        $this.Value = $value
    }

    [string]ToHexValue() {
        return "0x{0:x}" -f $this.Value
    }

    [string]ToString() {
        return $this.Name
    }

    [bool]Equals([object]$other) {
        if ($null -eq $other -or $this.GetType() -ne $other.GetType()) {
            return $false
        }
        $EType = [EncryptionType]$other
        return $EType.Name -eq $this.Name -and $EType.Value -eq $this.Value
    }
}

$script:NoEtype = [EncryptionType]::new("NONE", 0)
$script:DES_CRC = [EncryptionType]::new("DES_CRC", 0x1)
$script:DES_MD5 = [EncryptionType]::new("DES_MD5", 0x2)
$script:RC4 = [EncryptionType]::new("RC4", 0x4)
$script:AES128 = [EncryptionType]::new("AES128_SHA1", 0x08)
$script:AES256 = [EncryptionType]::new("AES256_SHA1", 0x10)
$script:AES_SK = [EncryptionType]::new("AES_SK", 0x20)
$script:AES128_SHA2 = [EncryptionType]::new("AES128-SHA2", 0x40)
$script:AES256_SHA2 = [EncryptionType]::new("AES256-SHA2", 0x80)

$script:EncryptionValues = [System.Collections.ArrayList]::new()
$script:EncryptionValues.Add($script:NoEtype) | Out-Null
$script:EncryptionValues.Add($script:DES_CRC) | Out-Null
$script:EncryptionValues.Add($script:DES_MD5) | Out-Null
$script:EncryptionValues.Add($script:RC4) | Out-Null
$script:EncryptionValues.Add($script:AES128) | Out-Null
$script:EncryptionValues.Add($script:AES256) | Out-Null
$script:EncryptionValues.Add($script:AES_SK) | Out-Null
$script:EncryptionValues.Add($script:AES128_SHA2) | Out-Null
$script:EncryptionValues.Add($script:AES256_SHA2) | Out-Null

function Find-SharedEType {
    param(
        [int]$A,
        [int]$B
    )
    return $A -band $B
}

function Find-MaxEtype {
    param(
        [int]$EType
    )
    $maxEtype = $null
    foreach($etypePair in $script:EncryptionValues) {
        if (($Etype -band $etypePair.Value) -eq $etypePair.Value) {
            $maxEtype = $etypePair
        }
    }
    return $maxEtype
}

function Execute-Parameters {
    param(
        [int]$SourceSET,
        [int]$TargetSET,
        [int]$KdcSET,
        [bool]$Subsession,
        [bool]$TGT,
        [bool]$DFL
    )
    $sharedEtype = 0
    $domainSET = $script:DomainSET
    $krbtgtSET = $script:KrbtgtSET
    if ($DFL) {
        $domainSET = $domainSET -bor $script:AesSha2Bits
        $domainSET = $domainSET -band $(-bnot $script:RC4.Value)
        $krbtgtSET = $krbtgtSET -bor $script:AesSha2Bits
    }

    if ($TGT) {
        $sharedEtype = Find-SharedEType -A $SourceSET -B $krbtgtSET
    } else {
        $sharedEtype = Find-SharedEType -A $SourceSET -B $TargetSET

        if (-not $Subsession) {
            # This Etype also needs to be shared with the KDC issuing the ticket
            $kdcSharedEType = Find-SharedEType -A $KdcSET -B $sharedEtype

            # This KDC needs to be shared by the domain SET
            $sharedEtype = Find-SharedEType -A $kdcSharedEType -B $domainSET
        }
    }

    $highestEtype = Find-MaxEtype -EType $sharedEtype
    return "Shared EType: $($highestEtype.ToHexValue()) $highestEtype"
}

if ($PSBoundParameters.Count -eq 0) {
    Add-Type -AssemblyName PresentationCore, PresentationFramework

    # Define the XAML
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Kerberos Calculator" Height="300" Width="400">
    <StackPanel Margin="10">
        <StackPanel Orientation="Horizontal" Margin="5">
            <Label Content="Source SET:" Width="100"/>
            <TextBox Name="tb_sourceSET" Width="200" Text="0x1c"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" Margin="5">
            <Label Content="Target SET:" Width="100"/>
            <TextBox Name="tb_targetSET" Width="200" Text="0x1c"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" Margin="5">
            <Label Content="KDC SET:" Width="100"/>
            <TextBox Name="tb_kdcSET" Width="200" Text="0x1c"/>
        </StackPanel>
        <CheckBox Name="cb_tgt" Margin="5" Content="TGT"/>
        <CheckBox Name="cb_ssk" Margin="5" Content="Subsession Key"/>
        <CheckBox Name="cb_dfl" Margin="5" Content="2025+ DFL"/>
        <TextBlock Name="tb_result" HorizontalAlignment="Left" VerticalAlignment="Top" TextWrapping="Wrap"/>
        <Button Name="b_calculate" Content="Calculate"/>
</StackPanel>
</Window>
"@

    $window = [Windows.Markup.XamlReader]::Parse($xaml)
    [xml]$xml = $xaml
    $xml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name $_.Name -Value $Window.FindName($_.Name) }
    $b_calculate.Add_Click({
        $sourceSET = 0
        try {
            $sourceSET = [Convert]::ToInt32($tb_sourceSET.Text, 16)
        } catch {
            $tb_result.Text = "Invalid input of $($tb_sourceSET.Text) in Source SET"
            return
        }

        $targetSET = 0
        try {
            $targetSET = [Convert]::ToInt32($tb_targetSET.Text, 16)
        } catch {
            $tb_result.Text = "Invalid input of $($tb_targetSET.Text) in Target SET"
            return
        }

        $kdcSET = 0
        try {
            $kdcSET = [Convert]::ToInt32($tb_kdcSET.Text, 16)
        } catch {
            $tb_result.Text = "Invalid input of $($tb_kdcSET.Text) in KDC SET"
            return
        }

        $tb_result.Text = $(Execute-Parameters -SourceSET $sourceSET `
                            -TargetSET $targetSET `
                            -KdcSET $kdcSET -TGT $cb_tgt.IsChecked `
                            -Subsession $cb_ssk.IsChecked -DFL $cb_dfl.IsChecked)
    })
    # Show the window
    $window.ShowDialog() | Out-Null
} else {
    Write-Host $(Execute-Parameters -SourceSET $SourceSET -TargetSET $TargetSET -KdcSET $KdcSET -TGT $TGT -Subsession $Subsession -DFL $DFL)
}

