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

Script Name	: mdiSensorProxyConfiguration.psm1
Description	: Manage (get, set, clear) the Defender for Identity Sensor proxy configuration
Author		: Martin Schvartzman, Microsoft
Last Update	: 2023/04/20
Version		: 0.1
Keywords	: MDI, Deployment

#>

#Requires -RunAsAdministrator


function Get-mdiSensorBinPath {
    $wmiParams = @{
        Namespace   = 'root\cimv2'
        Class       = 'Win32_Service'
        Property    = 'PathName'
        Filter      = 'Name="AATPSensor"'
        ErrorAction = 'Stop'
    }
    try {
        (Get-WmiObject @wmiParams | Select-Object -ExpandProperty PathName) -replace '"|Microsoft\.Tri\.Sensor\.exe', ''
    } catch {
        $null
    }
}


function Stop-mdiSensor {
    Stop-Service -Name AATPSensorUpdater -Force
}


function Start-mdiSensor {
    Start-Service -Name AATPSensorUpdater
}


function Get-mdiSensorConfiguration {
    $sensorBinPath = Get-mdiSensorBinPath
    if ($null -eq $sensorBinPath) {
        $sensorConfiguration = $null
    } else {
        $sensorConfigurationPath = Join-Path -Path $sensorBinPath -ChildPath 'SensorConfiguration.json'
        $sensorConfiguration = Get-Content -Path $sensorConfigurationPath -Raw | ConvertFrom-Json
    }
    $sensorConfiguration
}


function Get-mdiEncryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes(
        $Credential.GetNetworkCredential().Password
    )
    $encrypted = $rsaPublicKey.Encrypt($bytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $encryptedPassword = [System.Convert]::ToBase64String($encrypted)

    $store.Close()
    $encryptedPassword
}


function Get-mdiDecryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [string] $EncryptedPassword
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

    $encrypted = [System.Convert]::FromBase64String($EncryptedPassword)
    $bytes = $rsaPublicKey.Decrypt($encrypted, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($bytes)

    $store.Close()
    $decryptedPassword
}


function Get-mdiSensorProxyConfiguration {
    $sensorConfiguration = Get-mdiSensorConfiguration
    if ($null -eq $sensorConfiguration) {
        $proxyConfiguration = $null
    } else {
        $proxyConfiguration = [PSCustomObject]@{
            IsProxyEnabled               = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.Url)
            IsAuthenticationProxyEnabled = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.UserName)
            Url                          = $sensorConfiguration.SensorProxyConfiguration.Url
            UserName                     = $sensorConfiguration.SensorProxyConfiguration.UserName
        }
    }
    $proxyConfiguration
}


function Set-mdiSensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)] [string] $ProxyUrl,
        [Parameter(Mandatory = $false)] [PSCredential] $Credential
    )
    $operation = if ([string]::IsNullOrEmpty($ProxyUrl)) { 'Clear' } else { 'Set' }
    if ($PSCmdlet.ShouldProcess('MDI sensor proxy configuration', $operation)) {
        $sensorConfiguration = Get-mdiSensorConfiguration
        if ($null -eq $sensorConfiguration) {
            throw 'Cannot read sensor configuration.'
        }
        if ([string]::IsNullOrEmpty($ProxyUrl)) {
            $sensorConfiguration.SensorProxyConfiguration = $null
        } else {
            if ($Credential) {
                $thumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                    '$type'                   = 'SensorProxyConfiguration'
                    Url                       = $ProxyUrl
                    UserName                  = $Credential.UserName
                    EncryptedUserPasswordData = [PSCustomObject]@{
                        '$type'               = 'EncryptedData'
                        EncryptedBytes        = Get-mdiEncryptedPassword -CertificateThumbprint $thumbprint -Credential $Credential
                        SecretVersion         = $null
                        CertificateThumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                    }
                }
            } else {
                $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                    '$type' = 'SensorProxyConfiguration'
                    Url     = $ProxyUrl
                }
            }
        }
        Stop-mdiSensor
        $sensorConfiguration | ConvertTo-Json |
            Set-Content -Path (Join-Path -Path (Get-mdiSensorBinPath) -ChildPath 'SensorConfiguration.json')
        Start-mdiSensor
    }
}


function Clear-mdiSensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($PSCmdlet.ShouldProcess('MDI sensor proxy configuration', 'Clear')) {
        Set-mdiSensorProxyConfiguration -ProxyUrl $null
    }
}


Export-ModuleMember -Function *-mdiSensorProxyConfiguration