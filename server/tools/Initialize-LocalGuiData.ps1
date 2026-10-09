param(
    [Parameter(Mandatory = $true)][string]$SourceDataDirectory,
    [string]$TargetDataDirectory
)
$ErrorActionPreference = 'Stop'
$serverRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$clientRoot = [IO.Path]::GetFullPath((Join-Path $serverRoot '..'))
$source = (Resolve-Path -LiteralPath $SourceDataDirectory).Path
$target = if ($TargetDataDirectory) { [IO.Path]::GetFullPath($TargetDataDirectory) } else { Join-Path $serverRoot 'data' }
if (Test-Path -LiteralPath $target) { throw 'Target already exists; choose a new directory. Existing accounts are never overwritten.' }
$database = Join-Path $source 'richonline.sqlite3'
if (!(Test-Path -LiteralPath $database)) { throw 'Source account database is missing.' }
$executable = Join-Path $serverRoot 'RichOnline.Server.exe'
$bootstrap = Join-Path $serverRoot 'tests/fixtures/gameplay-bootstrap.json'
$config = [IO.File]::ReadAllText($bootstrap) | ConvertFrom-Json
$clientHash = (Get-FileHash -LiteralPath (Join-Path $clientRoot 'RnClient.exe') -Algorithm SHA256).Hash
if ($clientHash -ne $config.richonline_terminal_policy.client_sha256) { throw 'Client hash differs from the validated gameplay bootstrap.' }
# The service imports through SQLite's read-only backup API, including committed WAL data.
& $executable --import-db $database --data-dir $target
if ($LASTEXITCODE -ne 0) { throw 'Account database import failed.' }
$config.richonline_boss_game.client_root = [IO.Path]::GetRelativePath($target, $clientRoot).Replace('\', '/')
[IO.File]::WriteAllText((Join-Path $target 'lobby-bootstrap.json'), ($config | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
$manifest = [ordered]@{
    source = $source; target = $target; migratedAt = [DateTime]::UtcNow.ToString('o')
    databaseMethod = 'Server --import-db: read-only SQLite backup, no password reset or encoding adoption'
    bootstrapSource = $bootstrap; bootstrapSha256 = (Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash
    serverSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    clientSha256 = $clientHash
}
[IO.File]::WriteAllText((Join-Path $target 'gui-migration.json'), ($manifest | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Write-Output "GUI runtime prepared at $target"
