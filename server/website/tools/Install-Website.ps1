[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{7,40}$')][string]$ReleaseId,
    [string]$Root='D:\richonline\website',
    [string]$Address='103.156.25.81',
    [int]$Port=18743
)
$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath $Archive).Hash -ne $ArchiveSha256) {throw 'Archive checksum mismatch.'}
$release=Join-Path $Root "releases\$ReleaseId"
if(Test-Path -LiteralPath $release) {throw 'Release already exists.'}
$certificate=Join-Path $Root "acme\certificates\$Address.crt"
$key=Join-Path $Root "acme\certificates\$Address.key"
if(!(Test-Path $certificate) -or !(Test-Path $key)) {throw 'Website HTTPS certificate missing.'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($Archive)
try {
    foreach($entry in $zip.Entries) {
        $name=$entry.FullName.Replace('\','/')
        if($name.StartsWith('/') -or $name.Contains(':') -or $name.Split('/') -contains '..') {throw 'Unsafe archive path.'}
    }
} finally {$zip.Dispose()}
[IO.Compression.ZipFile]::ExtractToDirectory($Archive,$release)
$manifest=Get-Content -LiteralPath (Join-Path $release 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if(!$manifest.sourceCommit.StartsWith($ReleaseId)) {throw 'Source commit mismatch.'}
foreach($file in $manifest.files) {
    $path=[IO.Path]::GetFullPath((Join-Path $release $file.path))
    if(!$path.StartsWith($release+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe manifest path.'}
    if((Get-FileHash -LiteralPath $path).Hash -ne $file.sha256 -or (Get-Item $path).Length -ne $file.bytes) {throw 'Website file verification failed.'}
}
$state=Join-Path $Root 'state'
New-Item -ItemType Directory -Path $state -Force | Out-Null
& icacls $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0) {throw 'Website state ACL failed.'}
$configuration=@{PublicOrigin="https://${Address}:$Port";BindAddress=$Address;StateDirectory=$state;CertificateFile=$certificate;PrivateKeyFile=$key;PipeName='richonline-production';SourceCommit=$manifest.sourceCommit}
[IO.File]::WriteAllText((Join-Path $release 'website.json'),($configuration | ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
$taskName='RichOnline-Website'
$old=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$oldXml=if($old){Export-ScheduledTask -TaskName $taskName}else{$null}
if($old -and $old.Actions[0].Execute -notlike "$Root\releases\*\RichOnline.Website.exe") {throw 'Existing task is unmanaged.'}
$backup=Join-Path $Root ('backups\'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
if($oldXml){[IO.File]::WriteAllText((Join-Path $backup 'website-task.xml'),$oldXml)}
$current=Join-Path $Root 'current-release.json'
if(Test-Path $current){Copy-Item -LiteralPath $current -Destination $backup}
$principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$action=New-ScheduledTaskAction -Execute (Join-Path $release 'RichOnline.Website.exe') -WorkingDirectory $release
$firewall='RichOnline-Website-HTTPS'
try {
    if($old){Stop-ScheduledTask -TaskName $taskName;Start-Sleep -Seconds 2}
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Trigger (New-ScheduledTaskTrigger -AtStartup) -Force | Out-Null
    if(!(Get-NetFirewallRule -Name $firewall -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $firewall -DisplayName 'RichOnline website HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $Address -LocalPort $Port | Out-Null
    }
    Start-ScheduledTask -TaskName $taskName
    $ready=$false
    for($i=0;$i -lt 15;$i++) {
        Start-Sleep -Seconds 1
        try {
            $result=Invoke-RestMethod -Uri "https://${Address}:$Port/health" -TimeoutSec 3
            if($result.version -eq $manifest.sourceCommit -and $result.website -eq 'ready') {$ready=$true;break}
        } catch {}
    }
    if(!$ready){throw 'Website did not become ready.'}
    $record=@{releaseId=$ReleaseId;sourceCommit=$manifest.sourceCommit;directory=$release;origin=$configuration.PublicOrigin;installedAt=[DateTime]::UtcNow.ToString('o');files=$manifest.files.Count}
    [IO.File]::WriteAllText($current,($record|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
    $renew=Join-Path $Root 'tools\Renew-WebsiteTls.ps1'
    Copy-Item -LiteralPath (Join-Path $release 'tools\Renew-WebsiteTls.ps1') -Destination $renew -Force
    $renewAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $renew"
    $renewSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'RichOnline-Website-Certificate' -Action $renewAction -Principal $principal -Settings $renewSettings -Trigger (New-ScheduledTaskTrigger -Daily -At '04:30') -Force | Out-Null
    $record|ConvertTo-Json -Compress
} catch {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if($oldXml){Register-ScheduledTask -TaskName $taskName -Xml $oldXml -Force | Out-Null;Start-ScheduledTask -TaskName $taskName}
    throw
}
