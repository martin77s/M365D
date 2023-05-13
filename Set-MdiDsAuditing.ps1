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

Script Name	: Set-MdiDsAuditing.ps1
Description	: Set the Microsoft Defender for Identity Directory Services (Object auditing, ADFS container and Configuration container) auditing
Author		: Martin Schvartzman, Microsoft
Last Update	: 2023/05/14
Version		: 0.1
Keywords	: MDI, Deployment, Configuration, Auditing

#>

#Requires -Version 5.0
#requires -Module ActiveDirectory

$ObjectAuditing = @{
    Path     = 'AD:\{0}'
    Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects
'@ | ConvertFrom-Csv
}

$ExchangeAuditing = @{
    Path     = 'AD:\CN=Configuration,{0}'
    Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,32,3,194
'@ | ConvertFrom-Csv
}

$AdfsAuditing = @{
    Path     = 'AD:\CN=ADFS,CN=Microsoft,CN=Program Data,{0}'
    Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,48,3,194
'@ | ConvertFrom-Csv
}

function Set-mdiSACLS {
    param(
        [Parameter(Mandatory)] $Auditing
    )

    $DefaultNamingContext = ([adsi]('LDAP://{0}/ROOTDSE' -f $env:USERDNSDOMAIN)).defaultNamingContext.Value
    $Path = $Auditing.Path -f $DefaultNamingContext

    $acls = Get-Acl -Path $Path -Audit -ErrorAction SilentlyContinue
    if ($acls) {
        foreach ($audit in $Auditing.Auditing) {
            $account = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
                    $audit.SecurityIdentifier)).Translate([System.Security.Principal.NTAccount]).Value
            $argumentList = @(
                [Security.Principal.NTAccount] $account,
                [System.DirectoryServices.ActiveDirectoryRights] $audit.AccessMask,
                [System.Security.AccessControl.AuditFlags] $audit.AuditFlagsValue,
                [guid]::Empty.Guid.ToString()
            )
            if ($audit.InheritedObjectAceType) {
                $argumentList += [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                $argumentList += [guid] $audit.InheritedObjectAceType
            } else {
                $argumentList += [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                $argumentList += [guid]::Empty.Guid.ToString()
            }
            $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $argumentList
            $acls.AddAuditRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acls
    } else {
        Write-Warning ('Path not found: {0}' -f $Path)
    }
}

# DS Object auditing
Set-mdiSACLS -Auditing $ObjectAuditing

# ADFS container auditing
Set-mdiSACLS -Auditing $AdfsAuditing

# Configuration container auditing
Set-mdiSACLS -Auditing $ExchangeAuditing