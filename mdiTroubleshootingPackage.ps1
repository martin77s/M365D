<#
 ==========[DISCLAIMER]===========================================================================================================
  This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.
  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
  INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
  code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software
  product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the
  Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or
  lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
 =================================================================================================================================

Script Name	: mdiTroubleshootingPackage.ps1
Description	: Collect domain and domain controllers configuration related to MDI, for support and troubleshooting purposes.
Author		: Martin Schvartzman, Microsoft
Last Update	: 2022/08/22
Version		: 0.4
Keywords	: MDI, Deployment, Troubleshooting, Configuration, Support

#>

#requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to where the environment report will be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain name to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'DistinguishedName path to the container where the DS auditing was set. Defaults to domain root')]
    [string] $DSAuditContainer = $null
)


#region Helper functions

function Get-mdiSensorServices {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Service'
        Property     = 'Name', 'PathName', 'State'
        Filter       = "Name LIKE 'AATPSensor%'"
        ErrorAction  = 'SilentlyContinue'
    }
    $services = Get-WmiObject @wmiParams
    @{
        Sensor        = $services | Where-Object { $_.Name -eq 'AATPSensor' }
        SensorUpdater = $services | Where-Object { $_.Name -eq 'AATPSensorUpdater' }
    }
}


function Get-mdiSensorVersion {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $PathName
    )
    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'CIM_DataFile'
        Property     = 'Version'
        Filter       = 'Name={0}' -f ($PathName -replace '\\', '\\')
        ErrorAction  = 'SilentlyContinue'
    }
    (Get-WmiObject @wmiParams).Version
}


function Get-mdiLatestKb {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_QuickfixEngineering'
        ErrorAction  = 'SilentlyContinue'
    }
    $latestKb = (Get-WmiObject @wmiParams |
            Sort-Object { $_.InstalledOn -as [DateTime] } -Descending | Select-Object -First 1).InstalledOn
    ([datetime]$latestKb).ToString()
}


function Get-mdiCaptureComponent {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $uninstallRegKey = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    foreach ($registryView in @('Registry32', 'Registry64')) {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, $registryView)
        $uninstallRef = $hklm.OpenSubKey($uninstallRegKey)
        $applications = $uninstallRef.GetSubKeyNames()

        foreach ($app in $applications) {
            $appDetails = $hklm.OpenSubKey($uninstallRegKey + '\' + $app)
            $appDisplayName = $appDetails.GetValue('DisplayName')
            $appVersion = $appDetails.GetValue('DisplayVersion')
            if ($appDisplayName -match 'npcap|winpcap') {
                $return = '{0} ({1})' -f $appDisplayName, $appVersion
            }
        }
        $hklm.Close()
    }
    $return
}


function Invoke-mdiRemoteCommand {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $CommandLine
    )

    $localFile = 'C:\Windows\Temp\{0}.tmp' -f [guid]::NewGuid().GUID
    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Process'
        Name         = 'Create'
        ArgumentList = '{0} 2>&1>{1}' -f $CommandLine, $localFile
        ErrorAction  = 'SilentlyContinue'
    }
    $processId = Invoke-WmiMethod @wmiParams
    # TODO: Wait for the specific process to complete
    Start-Sleep -Seconds 2

    try {
        # Read the file using SMB
        $remoteFile = $localFile -replace 'C:', ('\\{0}\C$' -f $ComputerName)
        $return = Get-Content -Path $remoteFile
        Remove-Item -Path $remoteFile -Force
    } catch {
        # Read the remote file using WMI
        $psmClassParams = @{
            Namespace    = 'root\Microsoft\Windows\Powershellv3'
            ClassName    = 'PS_ModuleFile'
            ComputerName = $ComputerName
        }
        $cimParams = @{
            CimClass   = Get-CimClass @psmClassParams
            Property   = @{ InstanceID = $localFile }
            ClientOnly = $true
        }
        $fileInstanceParams = @{
            InputObject  = New-CimInstance @cimParams
            ComputerName = $ComputerName
        }
        $fileContents = Get-CimInstance @fileInstanceParams
        $fileLengthBytes = $fileContents.FileData[0..3]
        [array]::Reverse($fileLengthBytes)
        $fileLength = [BitConverter]::ToUInt32($fileLengthBytes, 0)
        $fileBytes = $fileContents.FileData[4..($fileLength - 1)]
        $localTempFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Value $fileBytes -Encoding Byte -Path $localTempFile
        $return = Get-Content -Path $localTempFile
        Remove-Item -Path $localTempFile -Force
    }
    $return
}


function Get-mdiPowerScheme {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $commandLine = 'cmd.exe /c %windir%\system32\powercfg.exe /getactivescheme'
    $powerScheme = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    if ($powerScheme -match 'Power Scheme GUID:\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $return = [ordered]@{
            guid              = $Matches.guid
            name              = $Matches.name
            isHighPerformance = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }
    } else {
        $return = [ordered]@{
            details = $powerScheme
        }
    }
    $return
}


function Get-mdiAdvancedAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $commandLine = 'cmd.exe /c auditpol.exe /get /category:* /r'
    $advancedAuditing = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    $advancedAuditing |  ConvertFrom-Csv | Where-Object {
        $_.Subcategory -in ('Security System Extension', 'Distribution Group Management', 'Security Group Management',
            'Computer Account Management', 'User Account Management', 'Directory Service Access', 'Credential Validation')
    }
}


function Get-mdiDomainControllerCoverage {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    if ($PSCmdlet.ShouldProcess($Domain, 'Get MDI related configuration')) {

        Write-Verbose -Message "Searching for Domain Controllers in $Domain"
        $dcs = @(Get-ADDomainController -Server $Domain -Filter *  | ForEach-Object {
                [ordered]@{
                    FQDN = $_.Hostname
                    IP   = $_.IPv4Address
                    OS   = $_.OperatingSystem
                    IsGC = $_.IsGlobalCatalog
                }
            })
        Write-Verbose -Message "Found $($dcs.Count) Domain Controller(s)"

        foreach ($dc in $dcs) {

            Write-Verbose -Message "Getting sensor services status for $($dc.FQDN)"
            $services = Get-mdiSensorServices -ComputerName $dc.FQDN

            $dc.Add('SensorUpdater', $services['SensorUpdater'].State)
            $dc.Add('Sensor', $services['Sensor'].State)

            Write-Verbose -Message "Getting sensor version for $($dc.FQDN)"
            if ($services['Sensor']) {
                $dc.Add('SensorVersion', (
                        Get-mdiSensorVersion -ComputerName $dc.FQDN -PathName $services['Sensor'].PathName
                    )
                )
            }

            Write-Verbose -Message "Getting latest OS update date for $($dc.FQDN)"
            $dc.Add('LatestKb', (Get-mdiLatestKb -ComputerName $dc.FQDN))

            Write-Verbose -Message "Getting capturing component for $($dc.FQDN)"
            $dc.Add('CapturingComponent', (Get-mdiCaptureComponent -ComputerName $dc.FQDN))

            Write-Verbose -Message "Getting power settings for $($dc.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $dc.FQDN
            $dc.Add('powerSettings', $powerSettings)

            Write-Verbose -Message "Getting advanced auditing for $($dc.FQDN)"
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN
            $dc.Add('AdvancedAuditing', $advancedAuditing)

            [PSCustomObject]$dc
        }
    }
}


function Get-mdiDSAudit {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string] $DSAuditContainer = $null
    )

    if ($PSCmdlet.ShouldProcess($Domain, 'Get DS Auditing configuration')) {

        $drive = $Domain -replace '\.', '-'
        if (Get-PSDrive -Name $drive -PSProvider ActiveDirectory -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $drive -PSProvider ActiveDirectory -Force
        }
        $adDrive = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Server $Domain -Scope Global -Root '//RootDSE/'

        if (-not $DSAuditContainer) {
            $adPath = Join-Path -Path ('{0}:\' -f $drive) -ChildPath (Get-ADDomain -Server $Domain).DistinguishedName
        } else {
            $adPath = Join-Path -Path ('{0}:\' -f $drive) -ChildPath $DSAuditContainer
        }
        $audit = Get-Acl $adPath -Audit
        $rules = $audit.GetAuditRules($true, $false, [Security.Principal.NTAccount]) |
            Where-Object { $_.IdentityReference -eq 'Everyone' -and $_.ObjectType -eq ([guid]::NewGuid().Guid -replace '\w', 0) } |
                Select-Object -Property ObjectType, InheritedObjectType, IsInherited,
                @{N = 'ObjectFlags'; E = { $_.ObjectFlags.ToString() } },
                @{N = 'AuditFlags'; E = { $_.AuditFlags.ToString() } },
                @{N = 'InheritanceFlags'; E = { $_.InheritanceFlags.ToString() } },
                @{N = 'PropagationFlags'; E = { $_.PropagationFlags.ToString() } },
                @{N = 'InheritanceType'; E = { $_.InheritanceType.ToString() } },
                @{N = 'ActiveDirectoryRights'; E = { $_.ActiveDirectoryRights.ToString() } },
                @{N = 'IdentityReference'; E = { $_.IdentityReference.Value } }

        $rules
        Remove-PSDrive $drive
    }
}

#endregion


if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
$report = @{
    DomainControllers = Get-mdiDomainControllerCoverage -Domain $Domain
    DomainDSAudit     = Get-mdiDSAudit -Domain $Domain
}
$reportFile = Join-Path -Path $Path -ChildPath ('mdi-{0}.json' -f $Domain)
$report | ConvertTo-Json -Depth 100 | Out-File -FilePath $reportFile -Force
Write-Host ('Output file: {0}' -f (Resolve-Path -Path $reportFile))