# 在目标服务器执行：为已有原生发布配套迁移商城日期与地图选择策略。
# 不用本机测试数据库覆盖线上数据；迁移器始终从停服后的线上库生成新副本。
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{7,40}$')][string]$ExpectedRelease,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedExeSha256,
    [Parameter(Mandatory)][string]$Migrator,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$MigratorSha256,
    [Parameter(Mandatory)][string]$VerifiedClient,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ClientSha256,
    [string]$Root = 'D:\richonline',
    [switch]$UnlockBossMaps,
    [switch]$AllowActiveSessions
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$taskName = 'RichOnline-Server'
$pipeName = 'richonline-production'
$data = Join-Path $Root 'shared\data'
$configPath = Join-Path $data 'lobby-bootstrap.json'
$databasePath = Join-Path $data 'richonline.sqlite3'
$currentPath = Join-Path $Root 'deploy\current-release.json'
$release = Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($release.releaseId -ne $ExpectedRelease) { throw 'Release changed; inspect the current deployment first.' }
$exe = Join-Path $release.releaseDirectory 'RichOnline.Server.exe'
$control = Join-Path $release.releaseDirectory 'Invoke-NativeControl.ps1'
foreach ($item in @(@($exe,$ExpectedExeSha256),@($Migrator,$MigratorSha256),@($VerifiedClient,$ClientSha256))) {
    if ((Get-FileHash -LiteralPath $item[0] -Algorithm SHA256).Hash -ne $item[1]) { throw 'Input checksum mismatch.' }
}
function Invoke-Control([string]$Operation,[string]$Instance = '') {
    $parsed = @(& $control -PipeName $pipeName -Command $Operation -ExpectedInstance $Instance -AllowActiveSessions:$AllowActiveSessions | ConvertFrom-Json)
    $value = $parsed | Select-Object -Last 1
    if (!$value) { throw "No control response: $Operation" }
    if ($value.PSObject.Properties['value'] -and $value.PSObject.Properties['Count']) { $value = $value.value | Select-Object -Last 1 }
    if ($Operation -eq 'database.backup' -and [string]::IsNullOrWhiteSpace([string]$value.path)) {
        throw 'Control backup response has no database path; do not stop the service.'
    }
    return $value
}
function Require-Healthy($State) {
    if (!$State -or $State.state -ne 'running' -or !$State.lobbyReady -or !$State.gameListenerReady -or
        !$State.httpReady -or !$State.blackReady -or !$State.introReady -or !$State.inquiryReady -or
        $State.dataDirectory -ne $data) { throw 'Runtime health or persistent data directory mismatch.' }
}
$state = Invoke-Control 'status'
Require-Healthy $state
$process = Get-CimInstance Win32_Process -Filter "ProcessId = $($state.pid)"
$task = Get-ScheduledTask -TaskName $taskName
if ($process.ExecutablePath -ne $exe -or $task.Actions.Execute -ne $exe) { throw 'Task or actual process is not the expected release.' }
if ($null -eq $state.authenticatedSessions -or ($state.authenticatedSessions -ne 0 -and !$AllowActiveSessions)) {
    throw 'Cannot stop active or unknown sessions without explicit maintenance authorization.'
}
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (!$config.richonline_mall_policy -or $config.richonline_mall_policy.inventory_date_version -ne 'original_2005' -or
    $config.richonline_mall_policy.verified_client_compatibility_id) {
    throw 'This one-time migration requires the original_2005 configuration; inspect other states manually.'
}
$configHash = (Get-FileHash -LiteralPath $configPath).Hash
$id = 'gameplay-compat-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$backup = Join-Path (Join-Path $Root 'backups') $id
New-Item -ItemType Directory -Path $backup | Out-Null
Copy-Item -LiteralPath $configPath -Destination (Join-Path $backup 'lobby-bootstrap.before.json')
Copy-Item -LiteralPath $currentPath -Destination (Join-Path $backup 'current-release.before.json')
[IO.File]::WriteAllText((Join-Path $backup 'scheduled-task.xml'),(Export-ScheduledTask -TaskName $taskName))
$config.richonline_mall_policy.inventory_date_version = 'compat_2021_v1'
$config.richonline_mall_policy.verified_client_compatibility_id = 'richonline-inventory-date-2021-v1'
if ($UnlockBossMaps) { $config | Add-Member -NotePropertyName unlock_all_boss_maps_for_testing -NotePropertyValue $true -Force }
$config.provenance += '; Paired online inventory date migration to 2021; verified client required. Map selection policy is independent of runtime package gates.'
$candidateConfig = Join-Path $backup 'lobby-bootstrap.candidate.json'
[IO.File]::WriteAllText($candidateConfig,($config | ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
$onlineBackup = Invoke-Control 'database.backup'
$onlineBackupPath = [string]$onlineBackup.path
if ([string]::IsNullOrWhiteSpace($onlineBackupPath)) { throw 'Online backup response path is empty.' }
if (!(Test-Path -LiteralPath $onlineBackupPath -PathType Leaf)) { throw 'Online database backup was not produced.' }
# 在线备份可以在停服前预检；停服后仍必须重新规划，不能把预检快照当作最终数据。
$planPath = Join-Path $backup 'online-preflight.json'
& $Migrator plan $onlineBackupPath $VerifiedClient | Out-File -LiteralPath $planPath -Encoding UTF8
if ($LASTEXITCODE -ne 0) { throw 'Online backup migration preflight failed; live service is unchanged.' }
$plan = Get-Content -LiteralPath $planPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (!$plan.ready -or @($plan.unresolved).Count -ne 0) { throw 'Migration contains unresolved records.' }
if ((Get-FileHash -LiteralPath $configPath).Hash -ne $configHash) { throw 'Configuration changed during preparation.' }
$stopped = $false
$databaseChanged = $false
$configChanged = $false
$started = $false
$migrated = Join-Path $backup 'richonline.migrated.sqlite3'
$databaseBefore = Join-Path $backup 'richonline.before-activation.sqlite3'
$configBefore = Join-Path $backup 'lobby-bootstrap.before-activation.json'
try {
    Invoke-Control 'stop' $state.instanceId | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    while (Get-Process -Id $state.pid -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) { throw 'Expected process did not stop normally.' }
        Start-Sleep -Milliseconds 250
    }
    $stopped = $true
    if ((Get-FileHash -LiteralPath $configPath).Hash -ne $configHash) { throw 'Configuration changed before activation.' }
    $migrationOutput = Join-Path $backup 'migration-result.json'
    & $Migrator migrate-copy $databasePath $migrated $VerifiedClient | Out-File -LiteralPath $migrationOutput -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Offline migration failed; original database is retained.' }
    $migration = Get-Content -LiteralPath ($migrated + '.datemigration.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Get-FileHash -LiteralPath $migrated).Hash -ne $migration.migrated_sha256 -or
        (Get-FileHash -LiteralPath $migration.backup_path).Hash -ne $migration.backup_sha256) {
        throw 'Migration output or preserved source checksum mismatch.'
    }
    # File.Replace保留每个原文件。开始新服务前失败可完整恢复；开服后不自动回滚玩家数据。
    [IO.File]::Replace($migrated,$databasePath,$databaseBefore)
    $databaseChanged = $true
    [IO.File]::Replace($candidateConfig,$configPath,$configBefore)
    $configChanged = $true
    $started = $true
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(45)
    do {
        try { $next = Invoke-Control 'status' } catch { $next = $null }
        if ($next -and $next.state -eq 'running' -and $next.lobbyReady -and $next.gameListenerReady) { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    Require-Healthy $next
    if ($next.instanceId -eq $state.instanceId) { throw 'Instance did not change.' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($next.pid)"
    if ($process.ExecutablePath -ne $exe) { throw 'Restarted process path mismatch.' }
    $logPath = Join-Path (Join-Path $data 'logs') ('native-' + $next.pid + '.jsonl')
    $events = @(Get-Content -LiteralPath $logPath -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    $loaded = @($events | Where-Object { $_.event -eq 'richonline_mall_policy_loaded' -and
        $_.inventory_date_version -eq 2021 -and $_.verified_client_compatibility_id -eq 'richonline-inventory-date-2021-v1' })
    if ($loaded.Count -ne 1) { throw 'New runtime did not confirm the paired mall policy.' }
    $receipt = [ordered]@{ operation=$id; releaseId=$release.releaseId; sourceCommit=$release.sourceCommit;
        exeSha256=$ExpectedExeSha256; clientSha256=$ClientSha256; migratorSha256=$MigratorSha256;
        backupDirectory=$backup; onlineDatabaseBackup=$onlineBackupPath; dataDirectory=$data;
        configSha256=(Get-FileHash -LiteralPath $configPath).Hash; migratedDatabaseSha256=$migration.migrated_sha256;
        inventoryDateVersion='compat_2021_v1'; unlockBossMaps=[bool]$config.unlock_all_boss_maps_for_testing;
        activatedUtc=[DateTime]::UtcNow.ToString('o'); status=$next }
    $json = $receipt | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText((Join-Path $backup 'activated.json'),$json,(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $Root 'deploy\current-gameplay-compatibility.json'),$json,(New-Object Text.UTF8Encoding($false)))
    $json
} catch {
    $failure = $_
    if ($stopped -and !$started) {
        if ($configChanged) { [IO.File]::Replace($configBefore,$configPath,(Join-Path $backup 'failed-config.json')) }
        if ($databaseChanged) { [IO.File]::Replace($databaseBefore,$databasePath,(Join-Path $backup 'failed-database.sqlite3')) }
        Start-ScheduledTask -TaskName $taskName
        Write-Warning 'Pre-start failure: restored original files and requested the original task to start; verify its status.'
    } else {
        Write-Warning 'Inspect actual process and backups before further action; no live player data was automatically rolled back.'
    }
    throw $failure
}
