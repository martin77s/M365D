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

Script Name	: Test-MdiReadiness.ps1
Description	: Verify Microsoft Defender for Identity prerequisites are in place
Author		: Martin Schvartzman, Microsoft
Last Update	: 2022/09/18
Version		: 0.2
Keywords	: MDI, Deployment, Configuration, Support, Troubleshooting
Note		: Running the script on an environment with MDI already deployed will trigger RCE (Remote Code Execution) alerts

#>

#Requires -Version 5.0
#requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to a folder where the reports are be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain Name or FQDN to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Open the HTML report at the end of the collection process')]
    [switch] $OpenHtmlReport
)


#region Helper functions


function Invoke-mdiRemoteCommand {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $CommandLine
    )

    $localFile = 'C:\Windows\Temp\mdi-{0}.tmp' -f [guid]::NewGuid().GUID
    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Process'
        Name         = 'Create'
        ArgumentList = '{0} 2>&1>{1}' -f $CommandLine, $localFile
        ErrorAction  = 'SilentlyContinue'
    }
    $result = Invoke-WmiMethod @wmiParams
    $maxWait = [datetime]::Now.AddSeconds(15)

    $waitForProcessParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Process'
        Filter       = ("ProcessId='{0}'" -f $result.ProcessId)
    }

    if ($result.ReturnValue -eq 0) {
        do { Start-Sleep -Milliseconds 200 }
        while (([datetime]::Now -lt $maxWait) -and (Get-WmiObject @waitForProcessParams).CommandLine -eq $wmiParams.ArgumentList)
    }

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
    $details = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    if ($details -match 'Power Scheme GUID:\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $return = [pscustomobject]@{
            isPowerSchemeOk = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            details         = $details
        }
    } else {
        $return = [pscustomobject]@{
            isPowerSchemeOk = $false
            details         = $details
        }
    }
    $return
}


function Get-mdiRegitryValueSet {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedRegistrySet
    )

    $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    $details = foreach ($reg in $ExpectedRegistrySet) {

        $regKeyPath, $regValue, $expectedValue = $reg -split ','
        $regKey = $hklm.OpenSubKey($regKeyPath)
        $value = $regKey.GetValue($regValue)

        [pscustomobject]@{
            regKey        = '{0}\{1}' -f $regKeyPath, $regValue
            value         = $value
            expectedValue = $expectedValue
        }
    }

    $hklm.Close()
    $details
}


function Get-mdiNtlmAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedRegistrySet = @(
        'System\CurrentControlSet\Control\Lsa\MSV1_0,AuditReceivingNTLMTraffic,2',
        'System\CurrentControlSet\Control\Lsa\MSV1_0,RestrictSendingNTLMTraffic,1',
        'System\CurrentControlSet\Services\Netlogon\Parameters,AuditNTLMInDomain,7'
    )

    $details = Get-mdiRegitryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $expectedRegistrySet
    $return = [pscustomobject]@{
        isNtlmAuditingOk = @($details | Where-Object { $_.value -ne $_.expectedValue }).Count -eq 0
        details          = $details | Select-Object regKey, value
    }
    $return
}


function Get-mdiCertReadiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedRootCertificates = @(
        'D4DE20D05E66FC53FE1A50882C78DB2852CAE474'   # All customers, Baltimore CyberTrust Root
        , 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4' # Commercial, DigiCert Global Root G2
        , 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436' # USGov, DigiCert Global Root CA
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\Root",
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $details = $store.Certificates | Where-Object { $expectedRootCertificates -contains $_.Thumbprint }
    $store.Close()
    $return = [pscustomobject]@{
        isRootCertificatesOk = @($details).Count -gt 1
        details              = $details | Select-Object -Property Thumbprint, Subject, Issuer, NotBefore, NotAfter
    }
    $return
}


function Get-mdiAdvancedAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedAuditing = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Value
System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,3
System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,
'@ | ConvertFrom-Csv
    $properties = ($expectedAuditing | Get-Member -MemberType NoteProperty).Name

    $localTempFile = 'mdi-{0}.csv' -f [guid]::NewGuid().Guid
    $commandLine = 'cmd.exe /c auditpol.exe /backup /file:%temp%\{0} >NULL && cmd.exe /c type %temp%\{0}' -f $localTempFile
    $output = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    $advancedAuditing = $output | ConvertFrom-Csv | Where-Object {
        $_.Subcategory -in ('Security System Extension', 'Distribution Group Management', 'Security Group Management',
            'Computer Account Management', 'User Account Management', 'Directory Service Access', 'Credential Validation')
    } | Select-Object -Property $properties

    $compareParams = @{
        ReferenceObject  = $expectedAuditing
        DifferenceObject = $advancedAuditing
        Property         = $properties
    }
    $isAdvancedAuditingOk = $null -eq (Compare-Object @compareParams)
    $return = [pscustomobject]@{
        isAdvancedAuditingOk = $isAdvancedAuditingOk
        details              = $advancedAuditing
    }
    $return
}


function Get-mdiDsSacl {
    param (
        [Parameter(Mandatory = $true)] [string] $LdapPath,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedAuditing
    )

    $searcher = [System.DirectoryServices.DirectorySearcher]::new(([adsi]$LdapPath))
    $searcher.CacheResults = $False
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $searcher.PropertiesToLoad.AddRange(('ntsecuritydescriptor,distinguishedname,objectsid' -split ','))
    try {
        $result = ($searcher.FindOne()).Properties

        $appliedAuditing = [Security.AccessControl.RawSecurityDescriptor]::new($result['ntsecuritydescriptor'][0], 0) |
            ForEach-Object { $_.SystemAcl } | Select-Object *,
            @{N = 'AcessMaskDetails'; E = { ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask)) } },
            @{N = 'AuditFlagsValue'; E = { $_.AuditFlags.value__ } },
            @{N = 'AceFlagsValue'; E = { $_.AceFlags.value__ } }


        $properties = ($expectedAuditing | Get-Member -MemberType NoteProperty).Name
        $compareParams = @{
            ReferenceObject  = $expectedAuditing | Select-Object -Property $properties
            DifferenceObject = $appliedAuditing | Select-Object -Property $properties
            Property         = $properties
        }

        $return = [pscustomobject]@{
            isAuditingOk = @(Compare-Object @compareParams -ExcludeDifferent -IncludeEqual).Count -eq $expectedAuditing.Count
            details      = $appliedAuditing
        }
    } catch {
        $e = $_
        $return = [pscustomobject]@{
            isAuditingOk = $False
            details      = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        }
    }
    $return
}


function Get-mdiObjectAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message 'Getting MDI related DS Object auditing configuration'
    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2
'@ | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $return = @{
        isObjectAuditingOk = $result.isAuditingOk
        details            = $result.details
    }
    $return

}


function Get-mdiExchangeAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string] $DSAuditContainer = $null
    )

    Write-Verbose -Message 'Getting MDI related Exchange auditing configuration'

    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,32,3,194
'@ | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=Configuration,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $return = @{
        isExchangeAuditingOk = $result.isAuditingOk
        details              = $result.details
    }
    $return

}


function Get-mdiAdfsAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message 'Getting MDI related ADFS auditing configuration'

    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,48,3,194
'@ | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $return = @{
        isAdfsAuditingOk = $result.isAuditingOk
        details          = $result.details
    }
    $return
}


function Get-mdiDomainControllerReadiness {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message "Searching for Domain Controllers in $Domain"
    $dcs = @(Get-ADDomainController -Server $Domain -Filter *  | ForEach-Object {
            @{
                FQDN = $_.Hostname
                IP   = $_.IPv4Address
                OS   = $_.OperatingSystem
            }
        })
    Write-Verbose -Message "Found $($dcs.Count) Domain Controller(s)"

    foreach ($dc in $dcs) {


        if (Test-Connection -ComputerName $dc.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing power settings for $($dc.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $dc.FQDN
            $dc.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($dc.FQDN)"
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN
            $dc.Add('AdvancedAuditing', $advancedAuditing.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingDetails', $advancedAuditing.details)

            Write-Verbose -Message "Testing NTLM auditing for $($dc.FQDN)"
            $ntlmAuditing = Get-mdiNtlmAuditing -ComputerName $dc.FQDN
            $dc.Add('NtlmAuditing', $ntlmAuditing.isNtlmAuditingOk)
            $details.Add('NtlmAuditingDetails', $ntlmAuditing.details)

            Write-Verbose -Message "Testing certificates readiness for $($dc.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $dc.FQDN
            $dc.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)


        } else {
            $dc.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $dc.FQDN)
        }

        $dc.Add('Details', $details)
        [pscustomobject]$dc
    }

}


function Set-MdiReadinessReport {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object[]] $ReportData
    )

    $jsonReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.json"
    Write-Verbose "Creating detailed json report: $htmlReportFile" -Verbose
    $ReportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonReportFile -Force
    $jsonReportFilePath = (Resolve-Path -Path $jsonReportFile).Path

    $css = @'
<style>
body { font-family: Arial, sans-serif, 'Open Sans'; }
table { border-collapse: collapse; }
td, th { border: 1px solid #aeb0b5; padding: 5px; text-align: center; vertical-align: middle; }
tr:nth-child(even) { background-color: #f2f2f2; }
th { padding: 8px; text-align: left; background-color: #e4e2e0; color: #212121; }
.red    {background-color: #cd2026; color: #ffffff; }
.green  {background-color: #4aa564; color: #212121; }
}
</style>
'@
    $properties = [collections.arraylist] @($ReportData.DomainControllers | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Definition -match '^bool' }).Name
    $properties.Insert(0, 'FQDN')
    [void] $properties.Add('Comment')
    $htmlDCs = ((($ReportData.DomainControllers | Sort-Object FQDN | Select-Object $properties | ConvertTo-Html -Fragment) `
                -replace '<th>(?!FQDN)(?!Comment)(\w+)', '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
            -replace '<td>True', '<td class="green">True') `
        -replace '<td>False', '<td class="red">False' `
        -join [environment]::NewLine


    $htmlDS = ((($ReportData | Select-Object @{N = 'Domain'; E = { $Domain } },
                @{N = 'ObjectAuditing'; E = { $_.DomainObjectAuditing.isObjectAuditingOk } },
                @{N = 'ExchangeAuditing'; E = { $_.DomainExchangeAuditing.isExchangeAuditingOk } },
                @{N = 'AdfsAuditing'; E = { $_.DomainAdfsAuditing.isAdfsAuditingOk } }  | ConvertTo-Html -Fragment) `
                -replace '<th>(?!Domain)(\w+)', '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
            -replace '<td>True', '<td class="green">True') `
        -replace '<td>False', '<td class="red">False' `
        -join [environment]::NewLine

    $htmlContent = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>{0}</head><body>
<h2>MDI readiness report for <b>{1}</b></h2>
<h4>Domain Services readiness</h4>
{2}
<h4>Domain Controllers readiness</h4>
{3}
<br/>Full details file can be found at <a href='{4}'>{4}</a><br/>
<br/>Created at {5} by <a href='https://aka.ms/mdi/Test-MdiReadiness'>Test-MdiReadiness.ps1</a>
'@ -f $css, $domain, $htmlDS, $htmlDCs, $jsonReportFilePath, [datetime]::Now

    $htmlReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.html"
    Write-Verbose "Creating html report: $htmlReportFile" -Verbose
    $htmlContent | Out-File -FilePath $htmlReportFile -Force
    (Resolve-Path -Path $htmlReportFile).Path
}

#endregion


#region Main

if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
if ($PSCmdlet.ShouldProcess($Domain, 'Create MDI related configuration reports')) {
    $report = @{
        Domain                 = $Domain
        DomainControllers      = Get-mdiDomainControllerReadiness -Domain $Domain
        DomainAdfsAuditing     = Get-mdiAdfsAuditing -Domain $Domain
        DomainObjectAuditing   = Get-mdiObjectAuditing -Domain $Domain
        DomainExchangeAuditing = Get-mdiExchangeAuditing -Domain $Domain
    }

    $htmlReportFile = Set-MdiReadinessReport -Domain $Domain -Path $Path -ReportData $report
    if ($OpenHtmlReport) { Invoke-Item -Path $htmlReportFile }
}

#endregion