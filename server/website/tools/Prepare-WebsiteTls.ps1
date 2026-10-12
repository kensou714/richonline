[CmdletBinding()]
param(
    [string]$Root='D:\richonline\website',
    [string]$NginxRoot='D:\msu123\nginx-1.29.3',
    [string]$Address='103.156.25.81'
)
$ErrorActionPreference='Stop'
if($Address -ne '103.156.25.81') {throw 'Inspect the nginx virtual host before changing the address.'}
$config=Join-Path $NginxRoot 'conf\nginx.conf'
$webroot=Join-Path $Root 'acme-webroot'
New-Item -ItemType Directory -Path $webroot -Force | Out-Null
$before=[IO.File]::ReadAllText($config)
$marker='# RichOnline IP certificate challenge'
if(!$before.Contains($marker)) {
    # 只替换已核对的 HTTP 默认重定向段；其他域名的返回行为不变。
    $pattern='(?s)(server_name\s+localhost 103\.156\.25\.81 api\.msu123\.com;\s*)return 301 https://\$host\$request_uri;'
    if([regex]::Matches($before,$pattern).Count -ne 1) {throw 'Unexpected nginx layout; no files changed.'}
    $insert=@'
        # RichOnline IP certificate challenge
        location ^~ /.well-known/acme-challenge/ {
            root D:/richonline/website/acme-webroot;
            default_type text/plain;
            try_files $uri =404;
        }
        location / { return 301 https://$host$request_uri; }
'@
    $after=[regex]::Replace($before,$pattern,{param($match) $match.Groups[1].Value+$insert})
    $backup=$config+'.richonline-'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmss')+'.bak'
    Copy-Item -LiteralPath $config -Destination $backup
    [IO.File]::WriteAllText($config,$after,(New-Object Text.UTF8Encoding($false)))
    Push-Location $NginxRoot
    try {
        & .\nginx.exe -t
        if($LASTEXITCODE -ne 0) {throw 'nginx configuration rejected.'}
        & .\nginx.exe -s reload
        if($LASTEXITCODE -ne 0) {throw 'nginx reload failed.'}
    } catch {
        [IO.File]::WriteAllText($config,$before,(New-Object Text.UTF8Encoding($false)))
        & .\nginx.exe -s reload
        throw
    } finally {Pop-Location}
}
$acme=Join-Path $Root 'acme'
New-Item -ItemType Directory -Path $acme -Force | Out-Null
# ACME 账号与证书私钥仅管理员和 SYSTEM 可读，不进入发布包或输出。
& icacls $acme /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0) {throw 'Certificate directory ACL failed.'}
& (Join-Path $Root 'tools\lego.exe') run --accept-tos --account-id richonline-ip --domains $Address --profile shortlived --http --http.webroot $webroot --path $acme --no-random-sleep
if($LASTEXITCODE -ne 0) {throw 'Certificate issuance failed.'}
Get-ChildItem -LiteralPath (Join-Path $acme 'certificates') -Filter '*.crt' | Select-Object Name,Length
