# Run once in an elevated Windows PowerShell session on the destination server.
# Installs the transport only; does not start or replace RichOnline processes.
[CmdletBinding()]
param(
    [string]$PublicKeyPath = (Join-Path $PSScriptRoot 'richonline_deploy_ed25519.pub'),
    [string]$DeploymentRoot = 'D:\richonline',
    [ValidateRange(1, 65535)][int]$Port = 22,
    [string[]]$AllowedRemoteAddress = @('Any')
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated Windows PowerShell session.'
}

$publicKey = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [^\r\n]+)?$') {
    throw 'Expected one OpenSSH Ed25519 public key. Never copy the private key to the server.'
}
if (![IO.Path]::IsPathRooted($DeploymentRoot)) { throw 'DeploymentRoot must be an absolute path.' }
if (!(Test-Path -LiteralPath ([IO.Path]::GetPathRoot($DeploymentRoot)))) {
    throw 'The destination drive does not exist.'
}

$sshRoot = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshRoot 'sshd_config'
# Preserve existing SSH policy. Nonstandard installations require an explicit review.
if (Test-Path -LiteralPath $configPath) {
    $existingConfig = Get-Content -LiteralPath $configPath -Raw
    $ports = [regex]::Matches($existingConfig, '(?im)^\s*Port\s+(\d+)\s*(?:#.*)?$')
    $configuredPorts = @(if ($ports.Count) { $ports | ForEach-Object { [int]$_.Groups[1].Value } } else { 22 })
    if ($Port -notin $configuredPorts) { throw 'Requested port differs from existing SSH configuration. Existing configuration was not changed.' }
    if ($existingConfig -notmatch '(?im)^\s*Match\s+Group\s+administrators\s*$' -or
        $existingConfig -notmatch '(?im)^\s*AuthorizedKeysFile\s+__PROGRAMDATA__/ssh/administrators_authorized_keys\s*$') {
        throw 'Existing administrator key policy is nonstandard. Review it before adding deployment access.'
    }
} elseif (Get-Service sshd -ErrorAction SilentlyContinue) {
    throw 'An SSH service already exists without the standard configuration. Review it before proceeding.'
}

$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($capability.State -ne 'Installed') {
    $install = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($install.RestartNeeded) { throw 'OpenSSH installation requires a restart. Restart Windows and rerun this script.' }
}
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
if (!(Test-Path -LiteralPath $sshd)) { throw 'The Windows OpenSSH server executable was not found.' }
New-Item -ItemType Directory -Path $sshRoot -Force | Out-Null
if (!(Test-Path -LiteralPath $configPath)) {
    # Key authentication only for a new installation; no passwords stored here.
    $config = @"
Port $Port
PubkeyAuthentication yes
PasswordAuthentication no
Subsystem sftp sftp-server.exe
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
    [IO.File]::WriteAllText($configPath, $config + "`r`n", (New-Object Text.UTF8Encoding($false)))
}

$authorizedKeys = Join-Path $sshRoot 'administrators_authorized_keys'
$existingKeys = @(if (Test-Path -LiteralPath $authorizedKeys) { Get-Content -LiteralPath $authorizedKeys })
$keyMaterial = ($publicKey -split '\s+')[1]
if (!($existingKeys | Where-Object { ($_ -split '\s+') -contains $keyMaterial })) {
    if (Test-Path -LiteralPath $authorizedKeys) {
        Copy-Item -LiteralPath $authorizedKeys -Destination ($authorizedKeys + '.backup-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff'))
    }
    [IO.File]::WriteAllLines($authorizedKeys, [string[]]($existingKeys + $publicKey), (New-Object Text.UTF8Encoding($false)))
}
# Windows OpenSSH requires the shared administrator key file to be protected.
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
}
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
Set-Acl -LiteralPath $authorizedKeys -AclObject $acl

& (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe') -A
if ($LASTEXITCODE -ne 0) { throw 'SSH host-key generation failed.' }
. (Join-Path $PSScriptRoot 'SshHostKeyPermissions.ps1')
Repair-RichOnlineSshHostKeys -SshRoot $sshRoot
& $sshd -t
if ($LASTEXITCODE -ne 0) { throw 'SSH configuration validation failed; service was not started by this script.' }

$ruleName = "RichOnline-Deploy-SSH-$Port"
if (!(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $ruleName -DisplayName "RichOnline deployment SSH ($Port)" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress $AllowedRemoteAddress | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
New-Item -ItemType Directory -Path $DeploymentRoot -Force | Out-Null

Write-Output "SSH service: $((Get-Service sshd).Status)"
Write-Output "Deployment root: $DeploymentRoot"
Write-Output "SSH port: $Port"
Write-Output "Login account: $($identity.Name)"
Write-Output 'Server host-key fingerprint (retain for verification on the deploying computer):'
& (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe') -lf (Join-Path $sshRoot 'ssh_host_ed25519_key.pub')
if ($LASTEXITCODE -ne 0) { throw 'Could not display the SSH host-key fingerprint.' }
Write-Output 'If this host uses a cloud firewall or NAT, allow/map the selected SSH port there as well.'
