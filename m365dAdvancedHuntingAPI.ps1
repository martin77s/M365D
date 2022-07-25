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

Script Name	: m365dAdvancedHuntingAPI.ps1
Description	: Example for using the Advanced Hunting API
Author		: Martin Schvartzman, Microsoft
Last Update	: 2022-07-25
Keywords	: MDI, API, AdvancedHunting

References  :
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-advanced-hunting
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-best-practices
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-sample-powershell
#>


PARAM(
    [Parameter(Mandatory = $true)] $aadClientId,
    [Parameter(Mandatory = $true)] $aadClientSecret,
    [Parameter(Mandatory = $true)] $aadTenant,
    $ahQuery = 'IdentityDirectoryEvents | take 5'
)

# Authenticate to Azure AD with the application's client ID and secret
$resourceAppIdUri = 'https://api.security.microsoft.com'
$oAuthUri = "https://login.windows.net/$aadTenant/oauth2/token"
$authBody = [Ordered] @{
    resource      = $resourceAppIdUri
    client_id     = $aadClientId
    client_secret = $aadClientSecret
    grant_type    = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token

# Invoke the query
$url = 'https://api.security.microsoft.com/api/advancedhunting/run'
$headers = @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $token"
}
$body = ConvertTo-Json -InputObject @{ 'Query' = $ahQuery }
$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$response = $webResponse | ConvertFrom-Json
$results = $response.Results
$schema = $response.Schema

# Output the results schema
$schema

# Output the results
$results