param(
    [Parameter(Mandatory = $true)][string]$SourceDataDirectory,
    [string]$TargetDataDirectory
)
$ErrorActionPreference = 'Stop'
$serverRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resourceRoot = Join-Path $serverRoot 'config/resources'
$source = (Resolve-Path -LiteralPath $SourceDataDirectory).Path
$target = if ($TargetDataDirectory) { [IO.Path]::GetFullPath($TargetDataDirectory) } else { Join-Path $serverRoot 'data' }
if (Test-Path -LiteralPath $target) { throw 'Target already exists; choose a new directory. Existing accounts are never overwritten.' }
$database = Join-Path $source 'richonline.sqlite3'
if (!(Test-Path -LiteralPath $database)) { throw 'Source account database is missing.' }
$executable = Join-Path $serverRoot 'RichOnline.Server.exe'
$bootstrap = Join-Path $serverRoot 'config/lobby-bootstrap.template.json'
$config = [IO.File]::ReadAllText($bootstrap) | ConvertFrom-Json
$resourceManifestPath = Join-Path $resourceRoot 'manifest.json'
$resources = [IO.File]::ReadAllText($resourceManifestPath) | ConvertFrom-Json
$specification = [IO.File]::ReadAllText((Join-Path $serverRoot 'config/runtime-resources.json')) | ConvertFrom-Json
if ($resources.version -ne 1 -or $specification.version -ne 1 -or !$specification.files.Count) { throw 'Invalid server resource manifest.' }
$expectedFiles = @($specification.files) + @($specification.optional_files | Where-Object { Test-Path -LiteralPath (Join-Path $resourceRoot $_) -PathType Leaf })
if ($resources.files.Count -ne $expectedFiles.Count) { throw 'Resource manifest does not match runtime requirements.' }
foreach ($relative in $expectedFiles) {
    if (!$relative -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or ($relative -split '[/\\]') -contains '..') {
        throw "Invalid resource path: $relative"
    }
    $entry = @($resources.files | Where-Object { $_.path -eq $relative })
    $resource = Join-Path $resourceRoot $relative
    if ($entry.Count -ne 1 -or !(Test-Path -LiteralPath $resource -PathType Leaf) -or
        (Get-Item -LiteralPath $resource).Length -ne $entry[0].size -or
        (Get-FileHash -LiteralPath $resource -Algorithm SHA256).Hash -ne $entry[0].sha256) {
        throw "Server resource verification failed: $relative"
    }
}
# The service imports through SQLite's read-only backup API, including committed WAL data.
& $executable --import-db $database --data-dir $target
if ($LASTEXITCODE -ne 0) { throw 'Account database import failed.' }
$config.richonline_boss_game.client_root = [IO.Path]::GetRelativePath($target, $resourceRoot).Replace('\', '/')
[IO.File]::WriteAllText((Join-Path $target 'lobby-bootstrap.json'), ($config | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
$manifest = [ordered]@{
    source = $source; target = $target; migratedAt = [DateTime]::UtcNow.ToString('o')
    databaseMethod = 'Server --import-db: read-only SQLite backup, no password reset or encoding adoption'
    bootstrapSource = $bootstrap; bootstrapSha256 = (Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash
    serverSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    resourceRoot = $resourceRoot
    resourceManifestSha256 = (Get-FileHash -LiteralPath $resourceManifestPath -Algorithm SHA256).Hash
}
[IO.File]::WriteAllText((Join-Path $target 'gui-migration.json'), ($manifest | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Write-Output "GUI runtime prepared at $target"
