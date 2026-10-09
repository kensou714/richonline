param([switch]$InstallClientEntry)
$ErrorActionPreference = 'Stop'
$serverRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$clientRoot = [IO.Path]::GetFullPath((Join-Path $serverRoot '..'))
$publish = Join-Path $serverRoot 'admin/publish'
dotnet publish (Join-Path $serverRoot 'admin/RichOnline.Admin.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publish
if ($LASTEXITCODE -ne 0) { throw 'admin_publish_failed' }
$backup = Join-Path $serverRoot ('build-migration-backup/admin-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
foreach ($name in @('RichOnline.Admin.exe', 'RichOnline.Admin.launch.json')) {
    $destination = Join-Path $serverRoot $name
    if (Test-Path -LiteralPath $destination) { Copy-Item -LiteralPath $destination -Destination (Join-Path $backup ('server-' + $name)) }
}
Copy-Item -LiteralPath (Join-Path $publish 'RichOnline.Admin.exe') -Destination $serverRoot
$launch = Join-Path $serverRoot 'RichOnline.Admin.launch.json'
if (!(Test-Path -LiteralPath $launch)) { Copy-Item -LiteralPath (Join-Path $serverRoot 'admin/RichOnline.Admin.launch.json') -Destination $launch }
if ($InstallClientEntry) {
    foreach ($name in @('RichOnline.Admin.exe', 'RichOnline.Admin.launch.json')) {
        $destination = Join-Path $clientRoot $name
        if (Test-Path -LiteralPath $destination) { Copy-Item -LiteralPath $destination -Destination (Join-Path $backup ('client-' + $name)) }
    }
    Copy-Item -LiteralPath (Join-Path $publish 'RichOnline.Admin.exe') -Destination $clientRoot
    $config = [ordered]@{ server='server/RichOnline.Server.exe'; 'data-dir'='server/data'; client='RnClient.exe'; 'client-config'='local-server/fixtures/local.kpd'; 'client-profile'='richonline' }
    [IO.File]::WriteAllText((Join-Path $clientRoot 'RichOnline.Admin.launch.json'), ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
}
Write-Output "GUI installed in $serverRoot; previous entry files backed up to $backup"
