$uri = '<insert Webhook URL>'
$headers = @{
    "Content-Type" = "application/json"
}
$jsonPayload  = @"
{
    "id":"552adb8331a9553b11000008";
    "message_id":"542adb8331a9553b11000008",
    "title":"Server Upgrades",
    "datetime":"2015-04-03T18:38:57.326Z",
    "current_status":"Planned Maintenance",
    "infrastructure_affected":[
        {"component":"551ed627b556f14210000005", "container":"551ed5ac590f5a3b10000006"},
        {"component":"551ed627b556f14210000005", "container":"551ed5b1c9f9404110000005"}
    ],
    "components":[
        {"name":"Chat Service",
        "_id":"551ed627b556f14210000005"}
    ],
    "containers":[
        {"name":"East Server",
        "_id":"551ed5ac590f5a3b10000006"},
        {"name":"West Server",
        "_id":"551ed5b1c9f9404110000005"}
    ],
    "details":"We've completed upgrades for all East Servers. No issues so far. Moving on to West Servers next. Updates to follow.",
    "maintenance_url":"https://status.io/pages/maintenance/5516e01e2e55e4e917000005/5116e01e2e33e4e413000001",
    "status_page_url":"https://status.io/pages/5516e01e2e55e4e917000005"
}
"@

$body = ConvertTo-Json -InputObject $jsonPayload 
$response = invoke-webrequest -method Post -uri $uri -header $headers -Body $body -UseBasicParsing 
$response