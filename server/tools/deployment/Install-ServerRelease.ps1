# Execute on the target over the authenticated deployment channel.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{7,40}$')][string]$ReleaseId,
    [Parameter(Mandatory)][string]$PublicAddress,
    [string]$Root = 'D:\richonline'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ne $ArchiveSha256) { throw 'Release archive checksum mismatch.' }
$address = [Net.IPAddress]::Parse($PublicAddress)
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 required.' }
if (!(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $PublicAddress)) { throw 'PublicAddress must be assigned to this server.' }
$taskName = 'RichOnline-Server'
$pipeName = 'richonline-production'
$release = Join-Path (Join-Path $Root 'releases') $ReleaseId
$data = Join-Path $Root 'shared\data'
$currentPath = Join-Path $Root 'deploy\current-release.json'
if (Test-Path -LiteralPath $release) { throw 'Release directory already exists; use a new release ID.' }
foreach ($dir in @($Root, (Join-Path $Root 'deploy'), (Join-Path $Root 'backups'), $data)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\','/')
        if ($name.StartsWith('/') -or $name.Contains(':') -or $name.Split('/') -contains '..') { throw 'Unsafe archive path.' }
    }
} finally { $zip.Dispose() }
[IO.Compression.ZipFile]::ExtractToDirectory($Archive, $release)
$manifest = Get-Content -LiteralPath (Join-Path $release 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.releaseId -ne $ReleaseId) { throw 'Manifest release ID mismatch.' }
foreach ($file in $manifest.files) {
    $path = [IO.Path]::GetFullPath((Join-Path $release $file.path))
    if (!$path.StartsWith($release.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe manifest path.' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) { throw "Release checksum mismatch: $($file.path)" }
}
$control = Join-Path $release 'Invoke-NativeControl.ps1'
$configPath = Join-Path $data 'lobby-bootstrap.json'
$invokeControl = {
    param([string]$operation, [string]$expectedInstance = '')
    $arguments = @('-PipeName', $pipeName, '-Command', $operation)
    if ($expectedInstance) { $arguments += @('-ExpectedInstance', $expectedInstance) }
    # Windows PowerShell can emit a VoidTaskResult from async writes in older releases.
    $results = @(& $control @arguments | ConvertFrom-Json)
    if (!$results) { throw "Control command returned no JSON: $operation" }
    $results | Select-Object -Last 1
}
$previous = if (Test-Path -LiteralPath $currentPath) { Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($oldTask -and !$previous) { throw 'Existing task has no deployment manifest; manual reconciliation required.' }
if (!$previous -and (Test-Path -LiteralPath $configPath)) { throw 'Unmanaged runtime configuration exists; refusing to overwrite.' }
if (!$previous -and (Test-Path -LiteralPath (Join-Path $data 'richonline.sqlite3'))) { throw 'Unmanaged database exists; refusing a first-release activation.' }
$backup = Join-Path (Join-Path $Root 'backups') ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + $ReleaseId)
New-Item -ItemType Directory -Path $backup | Out-Null
$oldTaskXml = if ($oldTask) { Export-ScheduledTask -TaskName $taskName } else { $null }
if ($oldTaskXml) { [IO.File]::WriteAllText((Join-Path $backup 'scheduled-task.xml'), $oldTaskXml) }
if ($previous) {
    $state = & $invokeControl status
    if ($state.authenticatedSessions -ne 0) { throw 'Active players are connected; deployment refuses to stop their sessions.' }
    & $invokeControl database.backup | Out-Null
    & $invokeControl stop $state.instanceId | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    while (Get-Process -Id $state.pid -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) { throw 'Previous process did not stop.' }
        Start-Sleep -Milliseconds 250
    }
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $backup 'lobby-bootstrap.json')
    Copy-Item -LiteralPath $currentPath -Destination (Join-Path $backup 'current-release.json')
}
$createdProxies = @()
$createdFirewall = $false
$firewallName = 'RichOnline-Public-Gameplay'
$ports = @(18600,18602,18605,18606,18680)
try {
    if ($previous) {
        # Preserve operator policy on subsequent releases; only switch resources.
        $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } else {
        $config = Get-Content -LiteralPath (Join-Path $release 'lobby-bootstrap.template.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $config.network.bind_host = '127.0.0.1'
    $config.network.advertised_host = $PublicAddress
    $config.richonline_boss_game.advertised_ipv4 = @($address.GetAddressBytes() | ForEach-Object { [int]$_ })
    $config.richonline_boss_game.client_root = Join-Path $release 'resources'
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30), (New-Object Text.UTF8Encoding($false)))
    $exe = Join-Path $release 'RichOnline.Server.exe'
    $action = New-ScheduledTaskAction -Execute $exe -Argument "--data-dir `"$data`" --pipe $pipeName --client-profile richonline" -WorkingDirectory $release
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -Description 'RichOnline native server; immutable release, persistent shared data.'
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(45)
    do {
        try { $state = & $invokeControl status } catch { $state = $null }
        if ($state -and $state.lobbyReady -and $state.httpReady -and $state.gameListenerReady -and $state.blackReady -and $state.introReady -and $state.inquiryReady) { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    if (!$state -or !$state.lobbyReady -or !$state.httpReady -or !$state.gameListenerReady -or !$state.blackReady -or !$state.introReady -or !$state.inquiryReady) {
        throw 'New release failed its local control health check. Inspect shared/data/logs.'
    }
    $http = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:18680/gameinfo/RichNetLogin.txt' -TimeoutSec 10
    if ($http.StatusCode -ne 200 -or $http.Content -notmatch [regex]::Escape($PublicAddress)) { throw 'Server list health check failed.' }
    Start-Service iphlpsvc
    foreach ($port in $ports) {
        $registryKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
        $entry = Get-ItemProperty -LiteralPath $registryKey -Name "$PublicAddress/$port" -ErrorAction SilentlyContinue
        if ($entry) {
            if ($entry."$PublicAddress/$port" -ne "127.0.0.1/$port") { throw 'Conflicting port proxy configuration.' }
        } else {
            & netsh interface portproxy add v4tov4 "listenaddress=$PublicAddress" "listenport=$port" connectaddress=127.0.0.1 "connectport=$port" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Port proxy registration failed.' }
            $createdProxies += $port
        }
    }
    if (!(Get-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $firewallName -DisplayName 'RichOnline lobby, game and read-only queries' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $PublicAddress -LocalPort $ports | Out-Null
        $createdFirewall = $true
    }
    $record = [ordered]@{releaseId=$ReleaseId; sourceCommit=$manifest.sourceCommit; exeSha256=(Get-FileHash $exe).Hash; releaseDirectory=$release; dataDirectory=$data; task=$taskName; pipe=$pipeName; activatedUtc=[DateTime]::UtcNow.ToString('o'); previous=$previous; status=$state; publicPorts=$ports; blackPortPolicy='loopback only, no authenticated binding'}
    [IO.File]::WriteAllText($currentPath,($record | ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
    $record | ConvertTo-Json -Depth 8
} catch {
    $failure = $_
    foreach ($port in $createdProxies) { & netsh interface portproxy delete v4tov4 "listenaddress=$PublicAddress" "listenport=$port" | Out-Null }
    if ($createdFirewall) { Remove-NetFirewallRule -Name $firewallName }
    try {
        $failedState = & $invokeControl status
        & $invokeControl stop $failedState.instanceId | Out-Null
    } catch { Write-Warning ('Graceful cleanup did not complete: ' + $_.Exception.Message) }
    if ($oldTaskXml) {
        Register-ScheduledTask -TaskName $taskName -Xml $oldTaskXml -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $backup 'lobby-bootstrap.json') -Destination $configPath -Force
        Start-ScheduledTask -TaskName $taskName
        Write-Warning 'Previous task and configuration restored. Database was not automatically rolled back.'
    } else {
        Disable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
    }
    throw $failure
}
