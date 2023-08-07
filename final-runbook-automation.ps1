param (
    [Parameter (Mandatory = $false)]
    [object] $WebHookData
)

# Replace with your Workspace ID
$customerId = "<replace with LAW workspace Id>"  

# Replace with your Primary Key
$SharedKey = "<replace with primary key from LAW workspace>"

# Specify the name of the record type that you'll be creating
$LogType = "DatabricksStatusAlerts"

# Optional name of a field that includes the timestamp for the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = ""

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

if ($WebHookData){
    # Body of the message.
    Write-Output 'The Request Body'
    Write-Output $WebHookData.RequestBody

    # Convert the body data from JSON
    $JsonPayload = ConvertFrom-Json -InputObject $WebHookData.RequestBody

    # View the full body data
    Write-Output 'The Full Body Data'
    Write-Output $JsonPayload

    $JsonString = $JsonPayload | ConvertTo-Json -Compress
    
$json = @"
[{  
    "JSONPayload": $JsonString,
    "GUIDValue": "9909ED01-A74C-4874-8ABF-D2678E3AE23D"
}]
"@
    # Submit the data to the API endpoint
    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
}
else {
    Write-Output 'No data received'
}