[CmdletBinding()]
param([string]$Root='D:\richonline\website',[string]$Address='103.156.25.81')
$ErrorActionPreference='Stop'
$certificate=Join-Path $Root "acme\certificates\$Address.crt"
$before=(Get-FileHash -LiteralPath $certificate).Hash
& (Join-Path $Root 'tools\lego.exe') run --accept-tos --account-id richonline-ip --domains $Address --profile shortlived --http --http.webroot (Join-Path $Root 'acme-webroot') --path (Join-Path $Root 'acme') --no-random-sleep
if($LASTEXITCODE -ne 0) {throw 'Certificate renewal failed; current website remains running.'}
if((Get-FileHash -LiteralPath $certificate).Hash -ne $before) {
    $task=Get-ScheduledTask -TaskName RichOnline-Website
    if($task.Actions[0].Execute -notlike "$Root\releases\*\RichOnline.Website.exe") {throw 'Unexpected website task path.'}
    Stop-ScheduledTask -TaskName RichOnline-Website
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName RichOnline-Website
}
