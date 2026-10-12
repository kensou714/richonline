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
# 发布副本增加官网导航，不改资料站的原始文件或数据。
$index=Join-Path $catalog 'index.html'
$html=[IO.File]::ReadAllText($index)
$html=$html.Replace('<nav id="catalog-nav" aria-label="游戏资料导航">','<nav id="catalog-nav" aria-label="游戏资料导航"><a href="/">官网首页</a><a href="/claim">领取代币</a><a href="/password">修改密码</a>')
[IO.File]::WriteAllText($index,$html,(New-Object Text.UTF8Encoding($false)))
$files=@(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object {
    [ordered]@{path=$_.FullName.Substring($out.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}
})
$manifest=[ordered]@{sourceCommit=$SourceCommit;kind='richonline-website';files=$files;validation='Compilation and static inspection only; no gameplay or account mutation tests'}
[IO.File]::WriteAllText((Join-Path $out 'manifest.json'),($manifest | ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
