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

Script Name	: mdiReinstallSensor.ps1
Description	: Remove and re-install the MDI sensor remotely. Requires PSRemoting.
Author		: Martin Schvartzman, Microsoft
Last Update	: 2022/07/21
Version		: 0.1
Keywords	: MDI, Deployment

#>

#requires -ver 5.1


#region Helper functions
function Remove-mdiSensor {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string[]] $ComputerName
    )

    foreach ($Computer in $ComputerName) {
        if ($PSCmdlet.ShouldProcess($Computer, 'Remove the MDI Sensor')) {
            Invoke-Command -ComputerName $Computer -ScriptBlock {
                $uninstallString = Get-ChildItem -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Recurse |
                    Get-ItemProperty -Name DisplayName -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -eq 'Azure Advanced Threat Protection Sensor' } | ForEach-Object {
                            Get-ItemProperty -Path $_.PSPath -Name QuietUninstallString
                        } | Select-Object -ExpandProperty QuietUninstallString
                if ($uninstallString) {
                    $setupPath = ($uninstallString -split '/')[0] -replace '"'
                    $p = Start-Process -FilePath $setupPath -ArgumentList @('/uninstall', '/quiet') -PassThru
                    do { Start-Sleep -Milliseconds 500 }
                    until ($p.StartTime.AddMinutes(2) -le (Get-Date) -or $p.HasExited)
                } else {
                    Write-Warning -Message ('MDI Sensor is not installed on {0}' -f $env:COMPUTERNAME)
                }
            }
        }
    }
}

function Copy-mdiSensorPackage {
    param(
        [Parameter(Mandatory = $true)] [System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)] [string] $LocalPath,
        [Parameter(Mandatory = $true)] [string] $RemotePath
    )

    $targetPath = Join-Path -Path $RemotePath -ChildPath 'Azure ATP Sensor Setup'
    Invoke-Command -Session $Session -ScriptBlock { [void](New-Item -Path $using:RemotePath -ItemType Directory -Force) }
    Get-ChildItem -Path $LocalPath | ForEach-Object {
        Copy-Item $_.FullName -Destination $targetPath -ToSession $Session -Force
    }
}

function Install-mdiSensor {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string[]] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $PackagePath,
        [Parameter(Mandatory = $true)] [SecureString] $AccessKey,
        [Parameter(Mandatory = $false)] [string] $RemotePath = 'C:\Temp\MDI'
    )

    if ($PSCmdlet.ShouldProcess(($ComputerName -join ', '), 'Copy and Install the MDI Sensor')) {

        Write-Verbose 'Extracting MDI Sensor package to a local temp directory'
        $tempPath = (New-Item -Path $env:TEMP -Name ([guid]::NewGuid().GUID) -ItemType Directory -Force).FullName
        Expand-Archive -Path $PackagePath -DestinationPath $tempPath

        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($AccessKey)
        $accessKeyString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)

        $session = New-PSSession -ComputerName $ComputerName
        $session | ForEach-Object {

            Write-Verbose ('Copying the MDI Sensor package to the {0}' -f $_.ComputerName)
            Copy-mdiSensorPackage -Session $_ -LocalPath $tempPath -RemotePath $RemotePath

            Write-Verbose ('Installing the MDI Sensor on {0}' -f $_.ComputerName)
            $result = Invoke-Command -Session $_ -ScriptBlock {
                $exePath = Join-Path -Path $using:RemotePath -ChildPath 'Azure ATP Sensor Setup\Azure ATP Sensor Setup.exe'
                $exeParams = '/quiet NetFrameworkCommandLineArguments="/q" AccessKey={0}' -f $using:accessKeyString
                $exitCode = (Start-Process -FilePath $exePath -ArgumentList $exeParams -Wait -PassThru).ExitCode
                if ($exitCode -ne 0) {
                    $log = (Get-ChildItem $env:TEMP -Filter 'Azure Advanced Threat Protection Sensor_*.log' | Sort-Object LastWriteTime -Descending)[0] | Get-Content
                }
                New-Object -TypeName PSObject -Property @{
                    exitCode = $exitCode
                    log = $log
                }
            }
            if ($result.exitCode -ne 0) {
                Set-Content -Path (Join-Path -Path .\ -ChildPath ('{0}-error.log' -f $_.ComputerName)) -Value $result.log -Force
                Write-Warning ('Installation failed on {0} with error {1}. Please check the logs.' -f $_.ComputerName, $result.exitCode)
            }
        }
    }
    Remove-PSSession -Session $session
    Remove-Item -Path $tempPath -Force -Recurse
}
#endregion


#region Script variables
$servers = @(
    'DC1', 'DC2', 'DC4', 'DC6'
)
$accessKey = Read-Host -Prompt 'Enter the access key' -AsSecureString
#endregion


Remove-mdiSensor -ComputerName $servers -Verbose

Install-mdiSensor -ComputerName $servers -PackagePath 'C:\Temp\MDI\Azure ATP Sensor Setup.zip' -AccessKey $accessKey -Verbose