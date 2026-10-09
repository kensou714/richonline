# Interactive wrapper: elevation, bootstrap, and a bounded diagnostic report.
[CmdletBinding()]
param([switch]$Elevated, [switch]$RepairHostKeys)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) { throw 'Administrator elevation was not granted.' }
    try {
        $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated'
        if ($RepairHostKeys) { $arguments += ' -RepairHostKeys' }
        $child = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        exit $child.ExitCode
    } catch {
        Write-Host ('Administrator elevation failed: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

$reportPath = Join-Path $PSScriptRoot 'deploy-diagnostics.txt'
$report = New-Object 'System.Collections.Generic.List[string]'
function Add-ReportSection {
    param([string]$Title, [scriptblock]$Action)
    $report.Add('=== ' + $Title + ' ===')
    try {
        $result = (& $Action | Out-String -Width 220).Trim()
        if (!$result) { $result = '(no output)' }
        $report.Add($result)
    } catch {
        $report.Add($_.Exception.Message)
    }
    $report.Add('')
}

Write-Host 'RichOnline deployment connection setup' -ForegroundColor Cyan
Write-Host 'No password or private key is read by this tool. Game processes and databases are not changed.'
$report.Add('UTC time: ' + [DateTime]::UtcNow.ToString('o'))
Add-ReportSection 'Windows' {
    Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture
}
Add-ReportSection 'SSH service before bootstrap' {
    Get-CimInstance Win32_Service -Filter "Name='sshd'" | Format-List Name, State, StartMode, StartName, PathName, ExitCode
}

$exitCode = 1
try {
    & {
        if ($RepairHostKeys) {
            $service = Get-Service -Name sshd
            if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Output 'SSH service is already running; no permissions changed or service restart performed.'
            } else {
                . (Join-Path $PSScriptRoot 'SshHostKeyPermissions.ps1')
                Repair-RichOnlineSshHostKeys -SshRoot (Join-Path $env:ProgramData 'ssh')
                Start-Service -Name sshd
                $service = Get-Service -Name sshd
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(10))
            }
            Write-Output ('SSH service: ' + (Get-Service -Name sshd).Status)
        } else {
            & (Join-Path $PSScriptRoot 'Initialize-DeployChannel.ps1')
        }
    } *>&1 | ForEach-Object {
        $line = ($_ | Out-String).TrimEnd()
        $report.Add($line)
        Write-Host $line
    }
    $exitCode = 0
    Write-Host 'SSH bootstrap completed.' -ForegroundColor Green
} catch {
    $report.Add('BOOTSTRAP FAILED: ' + $_.Exception.Message)
    $report.Add(($_ | Format-List * -Force | Out-String -Width 220).Trim())
    Write-Host ('Setup failed: ' + $_.Exception.Message) -ForegroundColor Red
}

Add-ReportSection 'SSH service after bootstrap' {
    Get-CimInstance Win32_Service -Filter "Name='sshd'" | Format-List Name, State, StartMode, StartName, PathName, ExitCode
}
Add-ReportSection 'SSH executable and configuration check' {
    $sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
    if (!(Test-Path -LiteralPath $sshd)) { throw 'System32 OpenSSH sshd.exe was not found.' }
    (Get-Item -LiteralPath $sshd).VersionInfo | Format-List FileVersion, ProductVersion, FileName
    $ErrorActionPreference = 'Continue'
    & $sshd -t -e 2>&1
    'Configuration check exit code: ' + $LASTEXITCODE
}
Add-ReportSection 'Recent OpenSSH events' {
    Get-WinEvent -FilterHashtable @{LogName = 'OpenSSH/Operational'; StartTime = (Get-Date).AddHours(-2)} -MaxEvents 12 | Format-List TimeCreated, Id, LevelDisplayName, Message
}
Add-ReportSection 'Recent SSH service-control errors' {
    Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddHours(-2)} |
        Where-Object { $_.Message -match 'sshd|OpenSSH' } |
        Select-Object -First 12 | Format-List TimeCreated, Id, LevelDisplayName, Message
}
Add-ReportSection 'TCP 22 listeners' {
    Get-NetTCPConnection -State Listen -LocalPort 22 | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
}
Add-ReportSection 'Recent SSH application crashes' {
    Get-WinEvent -FilterHashtable @{LogName = 'Application'; Id = 1000, 1001, 1026; StartTime = (Get-Date).AddHours(-2)} |
        Where-Object { $_.Message -match 'sshd|OpenSSH' } |
        Select-Object -First 6 | Format-List TimeCreated, Id, Message
}
Add-ReportSection 'Local SSH configuration (no key contents)' {
    $config = Join-Path $env:ProgramData 'ssh\sshd_config'
    Get-Content -LiteralPath $config | Where-Object { $_ -notmatch '^\s*(#|$)' }
}
Add-ReportSection 'SSH file permissions (no key contents)' {
    foreach ($name in @('sshd_config', 'ssh_host_ed25519_key', 'ssh_host_rsa_key', 'administrators_authorized_keys')) {
        $path = Join-Path (Join-Path $env:ProgramData 'ssh') $name
        if (Test-Path -LiteralPath $path) {
            Get-Acl -LiteralPath $path | Format-List Path, Owner, AccessToString
        }
    }
}
Add-ReportSection 'SSH host public-key fingerprint' {
    & (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe') -lf (Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub')
}

[IO.File]::WriteAllLines($reportPath, $report, (New-Object Text.UTF8Encoding($true)))
Write-Host ''
Write-Host ('Report saved to: ' + $reportPath) -ForegroundColor Cyan
Write-Host 'Copy this report back to the deploying computer. The report is not uploaded automatically.'
# This is an interactive tool. Keep the window available for the person launching it.
Read-Host 'Press Enter to close this window' | Out-Null
exit $exitCode
