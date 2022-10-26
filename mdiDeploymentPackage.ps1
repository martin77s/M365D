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

Script Name	: mdiDeploymentPackage.ps1
Description	: Download the MDI sensor installation accessKey and package (only if newer version is available) and get the current sensors details
Author		: Martin Schvartzman, Microsoft
Last Update	: 2022/10/26
Version		: 0.5
Keywords	: MDI, API, Deployment

#>

param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential] $Credential,

    [Parameter(Mandatory = $false)]
    $WorkspaceName = $null,

    [Parameter(Mandatory = $false)]
    [string] $Path = '.'
)

#region Helper functions
function Get-mdiToken {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential] $Credential
    )

    $params = @{
        'Body'        = @{
            'username'     = ($Credential).UserName
            'password'     = ($Credential).GetNetworkCredential().Password
            'grant_type'   = 'password'
            'redirect_uri' = 'urn:ietf:wg:oauth:2.0:oob' # PowerShell redirect Uri
            #'client_id'    = '1950a258-227b-4e31-a9cf-717495945fc2' # PowerShell client Id
            'client_id'    = '29d9ed98-a469-4536-ade2-f981bc1d605e' # Microsoft Authentication Broker
            'resource'     = '7b7531ad-5926-4f2d-8a1d-38495ad33e17' # Azure Advanced Threat Protection 1st party applicationId
        }
        'Method'      = 'Post'
        'ContentType' = 'application/x-www-form-urlencoded'
        'Uri'         = 'https://login.microsoftonline.com/common/oauth2/token'
    }
    $accessToken = Invoke-RestMethod @params | Select-Object -ExpandProperty access_token
    $accessToken

}


function Get-mdiSensorDeploymentAccessKey {
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName
    )
    $uri = 'https://{0}.atp.azure.com/api/workspace/sensorDeploymentAccessKey' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }
    $accessKey = (Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers  $headers -Method Get).Content |
        ConvertFrom-Json | Select-Object -ExpandProperty SensorDeploymentAccessKey
    $accessKey
}


function Get-mdiSensorPackage {
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName,
        [Parameter(Mandatory = $true)] [string] $path,
        [switch] $Force
    )

    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }

    $latestLocalVersion = Get-ChildItem -Path $path -Directory | Where-Object { $_.Name -as [version] } |
        Sort-Object -Property { [version] $_.Name } -Descending | Select-Object -First 1 -ExpandProperty Name

    $uri = 'https://{0}.atp.azure.com/api/sensors/deploymentPackageUri' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }
    $downloadUri = (Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers  $headers -Method Get).Content
    $cloudVersion = [version]($downloadUri -split '/')[5]

    if ($Force -or $cloudVersion -gt $latestLocalVersion) {
        $targetPath = (New-Item -Path $path -Name $cloudVersion.ToString() -ItemType Directory -Force)
        Invoke-WebRequest -Uri $downloadUri -Method Get -OutFile ('{0}\Azure ATP Sensor Setup.zip' -f $targetPath.FullName)
        $returnPath = $targetPath.FullName
    } else {
        $returnPath = Join-Path -Path (Get-Item -Path $path).FullName -ChildPath $latestLocalVersion
    }
    Get-ChildItem -Path $returnPath -Filter *.zip
}


function Get-mdiSensor {
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName
    )
    $uri = 'https://{0}.atp.azure.com/api/sensors' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }
    $sensorlist = (Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers  $headers -Method Get).Content
    $sensorlist | ConvertFrom-Json | Select-Object Id, SensorType, NetbiosName, RunningComputerFqdn,
    @{N = 'Version'; E = { $_.Software.VersionExternal } }, @{N = 'ServiceStatus'; E = { $_.DisplayServiceStatus } },
    @{N = 'SoftwareStatus'; E = { $_.Software.Status } }, @{N = 'DeploymentStatus'; E = { $_.Software.DeploymentStatus } },
    @{N = 'IsDelayedUpdateEnabled'; E = { $_.Software.IsDelayedUpdateEnabled } },
    @{N = 'DirectoryServicesClientConfiguration'; E = { $_.Configuration.DirectoryServicesClientConfiguration } },
    @{N = 'NetworkListenerConfiguration'; E = { $_.Configuration.NetworkListenerConfiguration } },
    @{N = 'SyslogClientConfiguration'; E = { $_.Configuration.SyslogClientConfiguration } },
    *Time, Description
}

#endregion


# If not supplied, extract the workspace name from the upn suffix
if (-not $WorkspaceName) {
    $workspaceName = ($Credential).UserName -replace '.*@(\w+)\..*', '$1'
}


Write-Verbose -Verbose -Message 'Authenticating with Azure and the MDI application'
$accessToken = Get-mdiToken -Credential $Credential


Write-Verbose -Verbose -Message 'Getting the access key for the workspace'
$accessKey = Get-mdiSensorDeploymentAccessKey -accessToken $accessToken -workspaceName $workspaceName


Write-Verbose -Verbose -Message 'Downloading latest sensor installation package'
$mdiSensorPackage = Get-mdiSensorPackage -accessToken $accessToken -workspaceName $workspaceName -path $Path
$mdiSensorPackage


Write-Verbose -Verbose -Message 'Get the registered sensors'
$sensors = Get-mdiSensor -accessToken $accessToken -workspaceName $workspaceName
$sensors