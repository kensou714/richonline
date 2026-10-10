[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceDirectory,
    [string]$DestinationDirectory
)
$ErrorActionPreference = 'Stop'
$serverRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory).Path
$destinationRoot = if ($DestinationDirectory) { [IO.Path]::GetFullPath($DestinationDirectory) } else { Join-Path $serverRoot 'config/resources' }
$specification = [IO.File]::ReadAllText((Join-Path $serverRoot 'config/runtime-resources.json')) | ConvertFrom-Json
if ($specification.version -ne 1 -or !$specification.files.Count) { throw 'Invalid runtime resource specification.' }
$sourcePrefix = $sourceRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$missingOptional = @($specification.optional_files | Where-Object { !(Test-Path -LiteralPath (Join-Path $sourceRoot $_) -PathType Leaf) })
$entries = @((@($specification.files) + @($specification.optional_files)) | ForEach-Object {
    $relative = [string]$_
    if (!$relative -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or ($relative -split '[/\\]') -contains '..' -or !$seen.Add($relative)) {
        throw "Invalid or duplicate resource path: $relative"
    }
    $sourcePath = [IO.Path]::GetFullPath((Join-Path $sourceRoot $relative))
    if ($missingOptional -contains $relative) { return }
    if (!$sourcePath.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase) -or !(Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Required server resource is missing: $relative"
    }
    [ordered]@{ path=$relative; size=(Get-Item -LiteralPath $sourcePath).Length; sha256=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash }
})
# Never overwrite operator-edited or currently loaded resources. Export a new directory for updates.
if (Test-Path -LiteralPath $destinationRoot) {
    if (!(Test-Path -LiteralPath (Join-Path $destinationRoot 'manifest.json') -PathType Leaf)) { throw 'Existing resource copy has no manifest; choose a new destination.' }
    foreach ($relative in $missingOptional) {
        if (Test-Path -LiteralPath (Join-Path $destinationRoot $relative)) { throw "Destination contains optional resource absent from source: $relative" }
    }
    foreach ($entry in $entries) {
        $existing = Join-Path $destinationRoot $entry.path
        if (!(Test-Path -LiteralPath $existing -PathType Leaf) -or (Get-FileHash -LiteralPath $existing -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw "Destination differs: $($entry.path). Choose a new -DestinationDirectory; existing resources are preserved."
        }
    }
    Write-Output "Resource copy already matches: $destinationRoot ($($entries.Count) files)"
    return
}
$parent = Split-Path -Parent $destinationRoot
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$staging = Join-Path $parent ('.resource-export-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null
foreach ($entry in $entries) {
    $target = Join-Path $staging $entry.path
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceRoot $entry.path) -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $entry.sha256) {
        throw "Resource copy verification failed: $($entry.path). Staging retained at $staging"
    }
}
$client = Join-Path $sourceRoot 'RnClient.exe'
$clientHash = if (Test-Path -LiteralPath $client -PathType Leaf) { (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash } else { $null }
$manifest = [ordered]@{
    version=1; exportedUtc=[DateTime]::UtcNow.ToString('o'); sourceDirectory=$sourceRoot
    sourceClientSha256=$clientHash; format='Unmodified KPD/EMP copies; no runtime access to sourceDirectory'
    files=$entries; missingOptional=$missingOptional
}
[IO.File]::WriteAllText((Join-Path $staging 'manifest.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $staging -Destination $destinationRoot
Write-Output "Exported $($entries.Count) verified resources to $destinationRoot"
