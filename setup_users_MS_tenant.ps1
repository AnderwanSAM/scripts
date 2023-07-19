param (
    [string]$filePath,
    [string]$tenantId,
    [string]$clientId,
    [string]$clientSecret,
    [string]$subscriptionSkuId
)

# Get the content of the file
$usernames = Get-Content -Path $filePath

# Define Azure AD details
$resource = "https://graph.microsoft.com"

# Request the access token
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$tokenBody = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}
$tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody
$accessToken = $tokenResponse.access_token

# Define headers
$headers = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type'  = 'application/json'
}

# Loop through each line in the file
foreach ($username in $usernames) {
    # Split the username and domain
    $split = $username.Split("@")
    
    # Create a hashtable for the body
    $body = @{
        accountEnabled = $true
        displayName = $split[0]
        mailNickname = $split[0]
        userPrincipalName = $username
        passwordProfile = @{
            forceChangePasswordNextSignIn = $true
            password = "xWwvJ]6NMw+bWH-d"
        }
    } | ConvertTo-Json

    # POST the data to Microsoft Graph API to create the user
    $response = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/users' -Method POST -Body $body -Headers $headers

    # Create a hashtable for the license body
    $licenseBody = @{
        addLicenses = @(
            @{
                disabledPlans = @()
                skuId = $subscriptionSkuId
            }
        )
        removeLicenses = @()
    } | ConvertTo-Json

    # Assign the license to the user
    $assignLicenseUri = 'https://graph.microsoft.com/v1.0/users/' + $response.id + '/assignLicense'
    Invoke-RestMethod -Uri $assignLicenseUri -Method POST -Body $licenseBody -Headers $headers
}
