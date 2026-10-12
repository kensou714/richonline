[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$CatalogRoot,
    [Parameter(Mandatory)][string]$SourceCommit
)
$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
$out=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $out) {throw 'Choose a new empty output directory.'}
& dotnet publish (Join-Path $project 'RichOnline.Website.csproj') -c Release -r win-x64 --self-contained true -o $out -p:DebugType=None
if($LASTEXITCODE -ne 0) {throw 'Website compilation failed.'}
$catalog=Join-Path $out 'catalog'
Copy-Item -LiteralPath $CatalogRoot -Destination $catalog -Recurse
# 页面外壳由wwwroot/index.html统一提供；资料目录只承载数据脚本和媒体。
foreach($name in @('catalog.js','app.js')) {
    if(!(Test-Path -LiteralPath (Join-Path $catalog $name))) {throw "Catalog asset missing: $name"}
}
Remove-Item -LiteralPath (Join-Path $catalog 'index.html'),(Join-Path $catalog 'styles.css') -ErrorAction Stop
$files=@(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object {
    [ordered]@{path=$_.FullName.Substring($out.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}
})
$manifest=[ordered]@{sourceCommit=$SourceCommit;kind='richonline-website';files=$files;validation='Compilation and static inspection only; no gameplay or account mutation tests'}
[IO.File]::WriteAllText((Join-Path $out 'manifest.json'),($manifest | ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
