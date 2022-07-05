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
Description	: Download the MDI sensor installation accessKey and package (only if newer version is available)
Author	: Martin Schvartzman, Microsoft
Last Update	: 2022-07-04
Keywords	: MDI, API, Deployment

#>

param(
    [string] $Path = '.',
    [switch] $Install
)

#region Helper functions
function Get-mdiToken {
    param (
        [Parameter(Mandatory = $true)] $user,
        [Parameter(Mandatory = $true)] $pass
    )

    $params = @{
        'Body'        = @{
            'username'     = $user
            'password'     = $pass
            'grant_type'   = 'password'
            'redirect_uri' = 'urn:ietf:wg:oauth:2.0:oob' # PowerShell redirect Uri
            'client_id'    = '1950a258-227b-4e31-a9cf-717495945fc2' # PowerShell client Id
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
        [switch] $Force
    )

    $latestLocalVersion = dir -Path $Path -Directory | Where-Object { $_.Name -as [version] } |
        Sort-Object -Property { [version] $_.Name } -Descending | Select-Object -First 1 -ExpandProperty Name

    $uri = 'https://{0}.atp.azure.com/api/sensors/deploymentPackageUri' -f $workspaceName
    $headers = @{
        'Authorization' = 'Bearer ' + $accessToken
    }
    $downloadUri = (Invoke-WebRequest -Uri $uri -UseBasicParsing -Headers  $headers -Method Get).Content
    $cloudVersion = [version]($downloadUri -split '/')[5]

    if ($Force -or $cloudVersion -gt $latestLocalVersion) {
        $targetPath = (New-Item -Path $Path -Name $cloudVersion.ToString() -ItemType Directory -Force)
        Invoke-WebRequest -Uri $downloadUri -Method Get -OutFile ('{0}\Azure ATP Sensor Setup.zip' -f $targetPath.FullName)
        $returnPath = $targetPath.FullName
    } else {
        $returnPath = Join-Path -Path (Get-Item -Path $Path).FullName -ChildPath $latestLocalVersion
    }
    dir -Path $returnPath -Filter *.zip
}
#endregion


# Replace hardcoded values with getting them securely from an Azure KeyVault (or similar)
$username = 'myuser@mytenant.onmicrosoft.com'
$password = 'my$3cur3dP4ssw0rd!'


# Extract the workspace name from the upn suffix. Can be set manually if needed.
$workspaceName = $username -replace '.*@(\w+)\..*', '$1'


Write-Verbose -Verbose -Message 'Authenticating with Azure and the MDI application'
$accessToken = Get-mdiToken $username $password


Write-Verbose -Verbose -Message 'Getting the access key for the workspace'
$accessKey = Get-mdiSensorDeploymentAccessKey -accessToken $accessToken -workspaceName $workspaceName


Write-Verbose -Verbose -Message 'Downloading latest sensor installation package'
$mdiSensorPackage = Get-mdiSensorPackage -accessToken $accessToken -workspaceName $workspaceName


if ($Install) {
    Write-Verbose -Verbose -Message 'Extracting installation package'
    $targetPath =  ($mdiSensorPackage.FullName -replace '\.zip$')
    Expand-Archive -Path $mdiSensorPackage -DestinationPath

    Write-Verbose -Verbose -Message 'Running installation package'
    $exePath = Join-Path -Path $targetPath -ChildPath 'Azure ATP Sensor Setup.exe'
    $exeParams = '/quiet NetFrameworkCommandLineArguments="/q" AccessKey={0}' -f $accessKey
    Start-Process -FilePath $exePath -ArgumentList $exeParams -Wait
}