# Reuse a separately provisioned, host-key-pinned SSH connection.
[CmdletBinding(DefaultParameterSetName = 'Command')]
param(
    [string]$Connection = 'richonline-deploy',
    [string]$SshConfigPath = (Join-Path $env:USERPROFILE '.ssh\richonline_deploy_config'),
    [Parameter(ParameterSetName = 'Command')]
    [string]$Command = 'whoami',
    [Parameter(Mandatory, ParameterSetName = 'Script')]
    [string]$ScriptPath,
    [Parameter(Mandatory, ParameterSetName = 'Upload')]
    [string]$Upload,
    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [string]$Download,
    [Parameter(Mandatory, ParameterSetName = 'Upload')]
    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $SshConfigPath -PathType Leaf)) {
    throw 'Deployment SSH configuration is missing. Provision and verify the connection first.'
}
if ($Connection -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$') { throw 'Invalid SSH host alias.' }
switch ($PSCmdlet.ParameterSetName) {
    'Command' {
        & ssh -F $SshConfigPath $Connection $Command
    }
    'Script' {
        $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ScriptPath).ProviderPath)
        # Windows PowerShell consumes UTF-16LE for EncodedCommand.
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ErrorActionPreference='Stop'; `$ProgressPreference='SilentlyContinue';`n" + $text))
        if ($encoded.Length -gt 7000) { throw 'Script is too large for the Windows command line. Upload it first and execute it with -Command.' }
        & ssh -F $SshConfigPath $Connection "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded"
    }
    'Upload' {
        # This server uses Windows OpenSSH 7.7; use its legacy SCP transport.
        # Restrict remote paths because that transport invokes a remote shell.
        if ($Destination -notmatch '^[A-Za-z]:/[A-Za-z0-9_./-]+$' -or $Destination -match '(^|/)\.\.(/|$)') {
            throw 'Use an absolute remote path with forward slashes, without spaces or shell characters.'
        }
        $source = (Resolve-Path -LiteralPath $Upload).ProviderPath
        if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Upload must be one file.' }
        & scp -O -F $SshConfigPath $source "${Connection}:$Destination"
    }
    'Download' {
        if ($Download -notmatch '^[A-Za-z]:/[A-Za-z0-9_./-]+$' -or $Download -match '(^|/)\.\.(/|$)') {
            throw 'Use an absolute remote path with forward slashes, without spaces or shell characters.'
        }
        $localTarget = [IO.Path]::GetFullPath($Destination)
        & scp -O -F $SshConfigPath "${Connection}:$Download" $localTarget
    }
}
if ($LASTEXITCODE -ne 0) { throw "Deployment transport failed with exit code $LASTEXITCODE." }
