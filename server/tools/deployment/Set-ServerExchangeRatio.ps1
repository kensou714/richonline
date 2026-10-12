# 在目标服务器执行配置发布：倍率同时控制wire30显示、wire42扣款和wire79入账。
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{7,40}$')][string]$ExpectedRelease,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedExeSha256,
    [Parameter(Mandatory)][double]$ExpectedRatio,
    [ValidateRange(1,2147483647)][int]$GoldPerToken = 1000,
    [string]$Root = 'D:\richonline',
    [switch]$AllowActiveSessions
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$currentPath=Join-Path $Root 'deploy\current-release.json'
$release=Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json
if($release.releaseId -ne $ExpectedRelease) {throw 'Release changed; inspect before updating.'}
$exe=Join-Path $release.releaseDirectory 'RichOnline.Server.exe'
if((Get-FileHash -LiteralPath $exe).Hash -ne $ExpectedExeSha256) {throw 'Unexpected executable hash.'}
$data=Join-Path $Root 'shared\data'
$configPath=Join-Path $data 'lobby-bootstrap.json'
$control=Join-Path $release.releaseDirectory 'Invoke-NativeControl.ps1'
$taskName='RichOnline-Server'
function Invoke-Control([string]$Operation,[string]$Instance='') {
    $items=@(& $control -PipeName 'richonline-production' -Command $Operation -ExpectedInstance $Instance -AllowActiveSessions:$AllowActiveSessions | ConvertFrom-Json)
    $result=$items | Select-Object -Last 1
    if(!$result) {throw "Empty control response: $Operation"}
    return $result
}
function Healthy($State) {
    return ($State -and $State.state -eq 'running' -and $State.dataDirectory -eq $data -and
        $State.lobbyReady -and $State.httpReady -and $State.gameListenerReady -and
        $State.blackReady -and $State.introReady -and $State.inquiryReady)
}
$state=Invoke-Control status
if(!(Healthy $state)) {throw 'Current runtime is not healthy.'}
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($state.pid)"
$task=Get-ScheduledTask -TaskName $taskName
if($process.ExecutablePath -ne $exe -or $task.Actions[0].Execute -ne $exe) {throw 'Task/process mismatch.'}
if($null -eq $state.authenticatedSessions -or ($state.authenticatedSessions -ne 0 -and !$AllowActiveSessions)) {
    throw 'Active or unknown sessions require maintenance authorization.'
}
$configHash=(Get-FileHash -LiteralPath $configPath).Hash
$config=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$hex=[string]$config.unknown_completion_hex
if($hex -notmatch '^[A-Fa-f0-9]{56}$') {throw 'Invalid completion configuration.'}
$bytes=[byte[]]::new(28)
for($i=0;$i -lt 28;$i++) {$bytes[$i]=[Convert]::ToByte($hex.Substring($i*2,2),16)}
if(![BitConverter]::IsLittleEndian) {throw 'Little-endian deployment host required.'}
$previousRatio=[BitConverter]::ToDouble($bytes,20)
if($previousRatio -ne $ExpectedRatio) {throw 'Exchange ratio changed; inspect before updating.'}
if($previousRatio -eq $GoldPerToken) {throw 'Requested ratio is already configured; no restart performed.'}
[Array]::Copy([BitConverter]::GetBytes([double]$GoldPerToken),0,$bytes,20,8)
$config.unknown_completion_hex=([BitConverter]::ToString($bytes)).Replace('-','')
if($config.policy_notes -and $config.policy_notes.PSObject.Properties['economy30']) {
    $config.policy_notes.economy30="Completion fields +4/+12 preserved; +20 is gold per token: $GoldPerToken. User-confirmed exchange policy."
}
$backup=Join-Path (Join-Path $Root 'backups') ('exchange-'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $backup | Out-Null
Copy-Item -LiteralPath $configPath -Destination (Join-Path $backup 'lobby-bootstrap.before.json')
Copy-Item -LiteralPath $currentPath -Destination $backup
[IO.File]::WriteAllText((Join-Path $backup 'scheduled-task.xml'),(Export-ScheduledTask -TaskName $taskName))
$candidate=Join-Path $backup 'lobby-bootstrap.candidate.json'
[IO.File]::WriteAllText($candidate,($config | ConvertTo-Json -Depth 40),(New-Object Text.UTF8Encoding($false)))
$db=Invoke-Control database.backup
if(!$db.path -or !(Test-Path -LiteralPath $db.path -PathType Leaf)) {throw 'Database backup not verified; refusing stop.'}
if((Get-FileHash -LiteralPath $configPath).Hash -ne $configHash) {throw 'Configuration changed during preparation.'}
$stopped=$false
$changed=$false
$started=$false
try {
    Invoke-Control stop $state.instanceId | Out-Null
    $deadline=(Get-Date).AddSeconds(20)
    while(Get-Process -Id $state.pid -ErrorAction SilentlyContinue) {
        if((Get-Date) -gt $deadline) {throw 'Old instance did not stop normally.'}
        Start-Sleep -Milliseconds 250
    }
    $stopped=$true
    if((Get-FileHash -LiteralPath $configPath).Hash -ne $configHash) {throw 'Configuration changed before activation.'}
    [IO.File]::Replace($candidate,$configPath,(Join-Path $backup 'lobby-bootstrap.replaced.json'))
    $changed=$true
    Start-ScheduledTask -TaskName $taskName
    $started=$true
    $deadline=(Get-Date).AddSeconds(45)
    do {
        try {$next=Invoke-Control status} catch {$next=$null}
        if((Healthy $next) -and $next.instanceId -ne $state.instanceId) {break}
        Start-Sleep -Milliseconds 500
    } while((Get-Date) -lt $deadline)
    if(!(Healthy $next) -or $next.instanceId -eq $state.instanceId) {throw 'New instance did not become healthy.'}
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($next.pid)"
    if($process.ExecutablePath -ne $exe) {throw 'New process path mismatch.'}
    $events=@(Get-Content -LiteralPath (Join-Path $data "logs\native-$($next.pid).jsonl") -Encoding UTF8 | ForEach-Object {$_ | ConvertFrom-Json})
    $loaded=@($events | Where-Object {$_.event -eq 'lobby_bootstrap_policy_loaded' -and $_.exchange_divisor -eq $GoldPerToken})
    if($loaded.Count -ne 1) {throw 'Runtime did not confirm the new exchange ratio.'}
    $receipt=[ordered]@{releaseId=$release.releaseId;sourceCommit=$release.sourceCommit;exeSha256=$ExpectedExeSha256;
        previousRatio=$previousRatio;goldPerToken=$GoldPerToken;backupDirectory=$backup;databaseBackup=$db.path;
        configSha256=(Get-FileHash -LiteralPath $configPath).Hash;activatedUtc=[DateTime]::UtcNow.ToString('o');status=$next}
    $json=$receipt | ConvertTo-Json -Depth 16
    [IO.File]::WriteAllText((Join-Path $backup 'receipt.json'),$json,(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $Root 'deploy\current-exchange-policy.json'),$json,(New-Object Text.UTF8Encoding($false)))
    $json
} catch {
    if($stopped -and !$started) {
        if($changed) {[IO.File]::Replace((Join-Path $backup 'lobby-bootstrap.replaced.json'),$configPath,(Join-Path $backup 'failed-config.json'))}
        Start-ScheduledTask -TaskName $taskName
        Write-Warning 'Restored pre-start configuration; verify runtime health.'
    } else {Write-Warning 'Inspect the actual instance and preserved backups before retrying. Database was not reverted.'}
    throw
}
