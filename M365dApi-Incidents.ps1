<#
    References:
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-supported?view=o365-worldwide
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-access?view=o365-worldwide
    https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents?view=o365-worldwide

    Required Microsoft Graph API Permissions:
    - Incident.ReadWrite.All
#>

function Get-AADToken {
    PARAM(
        [Parameter(mandatory)] [string] $ClientId,
        [Parameter(mandatory)] [string] $ClientSecret,
        [Parameter(mandatory)] [string] $TenantId
    )
    $authUri = 'https://login.windows.net/{0}/oauth2/token' -f $TenantId
    $resourceUri = 'https://api.security.microsoft.com'
    $authBody = [Ordered] @{
        resource      = $resourceUri
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
    }
    $authResponse = Invoke-RestMethod -Method Post -Uri $authUri -Body $authBody -ErrorAction Stop
    $authResponse.access_token
}


function Get-M365dGraphIncident {
    PARAM(
        [Parameter(mandatory)] [string] $Token,
        [string] $Filter = $null
    )
    $incidentsApiUri = 'https://api.security.microsoft.com/api/incidents'
    if ($Filter) {
        $incidentsApiUri = $incidentsApiUri + '?$filter=' + ($Filter -replace ' ', '+')
    }
    $headers = @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $token"
    }
    $webResponse = Invoke-WebRequest -Method Get -Uri $incidentsApiUri -Headers $headers -ErrorAction Stop
    ($webResponse | ConvertFrom-Json).value
}


function Update-M365dGraphIncident {
    PARAM(
        [Parameter(mandatory)] [string] $Token,
        [Parameter(mandatory)] [string] $IncidentId,
        [ValidateSet('Active ', 'Resolved', 'Redirected')] $Status = 'Resolved',
        [ValidateSet('Unknown', 'FalsePositive', 'TruePositive')] $Classification = 'Unknown',
        [ValidateSet('NotAvailable', 'Apt', 'Malware', 'SecurityPersonnel', 'SecurityTesting', 'UnwantedSoftware', 'Other')] $Determination = 'NotAvailable'
    )
    $incidentsApiUri = 'https://api.security.microsoft.com/api/incidents'
    $incidentUri = '{0}/{1}' -f $incidentsApiUri, $incidentId
    $headers = @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $token"
        'Prefer'        = 'return=representation'
    }
    $body = ConvertTo-Json -InputObject @{
        status         = $Status
        classification = $Classification
        determination  = $Determination
    }
    $webResponse = Invoke-WebRequest -Method PATCH -Uri $incidentUri -Headers $headers -Body $body -ErrorAction Stop
    ($webResponse | ConvertFrom-Json).value
}


# App registration details
$TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$ClientId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
$ClientSecret = 'clientsecretgoeshere',



# Authenticate to the Microsoft 365 Defender API with the application's client ID and secret
$token = Get-AADToken -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId


# Get incidents
$incidents = Get-M365dGraphIncident -Token $token -Filter "status eq 'Active'"


# Select an individual incident
$myIncident = $incidents[0]


# Update an incident
Update-M365dGraphIncident -Token $token -IncidentId $myIncident.incidentId -Status 'Resolved' -Classification 'Unknown' -Determination 'SecurityTesting'