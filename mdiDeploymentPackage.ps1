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
Last Update	: 2023/05/01
Version		: 0.7
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
    $sensorlist | ConvertFrom-Json | Select-Object @{N = 'SensorId'; E = { $_.Id } }, SensorType, NetbiosName, RunningComputerFqdn,
    @{N = 'Version'; E = { $_.Software.VersionExternal } }, @{N = 'ServiceStatus'; E = { $_.DisplayServiceStatus } },
    @{N = 'SoftwareStatus'; E = { $_.Software.Status } }, @{N = 'DeploymentStatus'; E = { $_.Software.DeploymentStatus } },
    @{N = 'IsDelayedUpdateEnabled'; E = { $_.Software.IsDelayedUpdateEnabled } },
    @{N = 'DirectoryServicesClientConfiguration'; E = { $_.Configuration.DirectoryServicesClientConfiguration } },
    @{N = 'NetworkListenerConfiguration'; E = { $_.Configuration.NetworkListenerConfiguration } },
    @{N = 'SyslogClientConfiguration'; E = { $_.Configuration.SyslogClientConfiguration } },
    *Time, Description
}


function Set-mdiSensorDelayedUpdate {
    [CmdletBinding(DefaultParameterSetName = 'Enable', SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName,
        [Parameter(Mandatory = $true)] [string] $SensorId,
        [Parameter(Mandatory = $false, ParameterSetName = 'Enable')] [switch] $EnableDelayedUpdates,
        [Parameter(Mandatory = $false, ParameterSetName = 'Disable')] [switch] $DisableDelayedUpdates
    )
    [bool]$IsDelayedDeploymentEnabled = switch ($PSCmdlet.ParameterSetName) {
        'Enable' { $EnableDelayedUpdates }
        'Disable' { -not $DisableDelayedUpdates }
    }
    if ($PSCmdlet.ShouldProcess($SensorId, ('{0} sensor delayed updates' -f $PSCmdlet.ParameterSetName))) {
        $params = @{
            'Uri'         = 'https://{0}.atp.azure.com/api/sensors/{1}/configuration/software' -f $workspaceName, $SensorId
            'Method'      = 'Put'
            'ContentType' = 'application/json'
            'Headers'     = @{
                'Authorization' = 'Bearer ' + $accessToken
            }
            'Body'        = @{
                'SensorId'                   = $SensorId
                'IsDelayedDeploymentEnabled' = $IsDelayedDeploymentEnabled
            } | ConvertTo-Json -Compress
        }
        Invoke-WebRequest @params | Out-Null
    }
}


function Get-mdiHealthAlerts {
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName
    )
    $uri = 'https://{0}.atp.azure.com/api/monitoringAlerts' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }

    $mdiSensors = Get-mdiSensor -accessToken $accessToken -workspaceName $workspaceName

    $monitoringAlerts = (Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers  $headers -Method Get).Content
    $monitoringAlerts | ConvertFrom-Json | Where-Object { $_.Status -eq 'Open' }  | ForEach-Object {
        if ($null -ne $_.AccountDomainName) {
            $DomainName = $_.AccountDomainName
        } else {
            $SensorId = @($_.SensorId) + $_.SensorIds
            $sensors = $mdiSensors | Where-Object { $SensorId -contains $_.SensorId }
            $SensorFqdn = $sensors.RunningComputerFqdn
            $DomainName = $sensors.RunningComputerFqdn -replace '^([^.]+).(.*)', '$2'
        }
        $_ | Select-Object @{N = 'HealthAlertId'; E = { $_.Id } }, Type, SystemCreationTime, SystemUpdateTime, Severity,
        @{N = 'DomainName'; E = { $DomainName } } , @{N = 'SensorFqdn'; E = { $SensorFqdn } }
    }
}


function Remove-mdiSyslogConfiguration {
    param(
        [Parameter(Mandatory = $true)] [string] $accessToken,
        [Parameter(Mandatory = $true)] [string] $workspaceName
    )
    $uri = 'https://{0}.atp.azure.com/api/workspace/configuration/syslogService' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }
    $result = Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers $headers -Method Delete
    if ($result.StatusCode -ne 200) {
        throw 'Failed to delete the Syslog service configuration'
    }
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


Write-Verbose -Verbose -Message 'Enable / Disable sensors delayed updates'
$sensorId = 'e8a39832-2a34-40f5-a9c6-bd8c40d7ed7b'
Set-mdiSensorDelayedUpdate -accessToken $accessToken -workspaceName $workspaceName -SensorId $sensorId -EnableDelayedUpdates
Set-mdiSensorDelayedUpdate -accessToken $accessToken -workspaceName $workspaceName -SensorId $sensorId -DisableDelayedUpdates


Write-Verbose -Verbose -Message 'Get the health alerts'
$healthAlerts = Get-mdiHealthAlerts -accessToken $accessToken -workspaceName $workspaceName
$healthAlerts