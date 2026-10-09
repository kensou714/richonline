# Host private keys must be owned by SYSTEM or Administrators and accessible
# only by those identities. An individual administrator is not equivalent to
# the Administrators group when sshd validates a key as LocalSystem.
# https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH
function Test-RichOnlineSshHostKeyAcl {
    param([Parameter(Mandatory)][Security.AccessControl.FileSecurity]$Acl)

    $trustedSids = @('S-1-5-18', 'S-1-5-32-544')
    if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedSids) { return $false }
    if (!$Acl.AreAccessRulesProtected) { return $false }
    $rightsBySid = @{}
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($sid -notin $trustedSids -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
        $rightsBySid[$sid] = [int]$rightsBySid[$sid] -bor [int]$rule.FileSystemRights
    }
    $fullControl = [int][Security.AccessControl.FileSystemRights]::FullControl
    foreach ($sid in $trustedSids) {
        if (([int]$rightsBySid[$sid] -band $fullControl) -ne $fullControl) { return $false }
    }
    return $true
}

function Repair-RichOnlineSshHostKeys {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SshRoot)

    $ErrorActionPreference = 'Stop'
    $root = (Resolve-Path -LiteralPath $SshRoot).ProviderPath
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing to change permissions through an SSH directory reparse point.'
    }
    $keys = @(Get-ChildItem -LiteralPath $root -File -Filter 'ssh_host_*_key' |
        Where-Object { $_.Name -match '^ssh_host_(rsa|dsa|ecdsa|ed25519)_key$' })
    if (!$keys.Count) { throw 'No standard SSH host private keys were found.' }

    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $desiredAcl = New-Object Security.AccessControl.FileSecurity
    $desiredAcl.SetOwner($systemSid)
    $desiredAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
        $desiredAcl.AddAccessRule($rule)
    }
    $ownerAndAccess = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $desiredSddl = $desiredAcl.GetSecurityDescriptorSddlForm($ownerAndAccess)
    $changes = @()
    foreach ($key in $keys) {
        if ($key.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw ('Refusing to change a host-key reparse point: ' + $key.Name)
        }
        $currentAcl = Get-Acl -LiteralPath $key.FullName
        if (!(Test-RichOnlineSshHostKeyAcl -Acl $currentAcl)) {
            $changes += [pscustomobject]@{
                Path = $key.FullName
                Sddl = $currentAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
                Hash = (Get-FileHash -LiteralPath $key.FullName -Algorithm SHA256).Hash
            }
        }
    }
    if (!$changes.Count) {
        Write-Output 'SSH host-key permissions already match the required SYSTEM / Administrators policy.'
        return
    }

    # Back up descriptors only, never private-key contents.
    $backupRoot = Join-Path $root 'richonline-deploy-acl-backups'
    if (Test-Path -LiteralPath $backupRoot) {
        if ((Get-Item -LiteralPath $backupRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The ACL backup directory must not be a reparse point.'
        }
    } else {
        New-Item -ItemType Directory -Path $backupRoot | Out-Null
    }
    $backupAcl = New-Object Security.AccessControl.DirectorySecurity
    $backupAcl.SetOwner($administratorsSid)
    $backupAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $backupAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $backupRoot -AclObject $backupAcl
    $backupPath = Join-Path $backupRoot ('host-key-acls-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '.clixml')
    $changes | Select-Object Path, Sddl | Export-Clixml -LiteralPath $backupPath
    Write-Output ('Previous host-key security descriptors saved to: ' + $backupPath)

    foreach ($change in $changes) {
        # Set-Acl can consume the descriptor's modification flags. Build a fresh
        # descriptor per file so every key gets both owner and DACL updates.
        $fileAcl = New-Object Security.AccessControl.FileSecurity
        $fileAcl.SetSecurityDescriptorSddlForm($desiredSddl, $ownerAndAccess)
        Set-Acl -LiteralPath $change.Path -AclObject $fileAcl
        $actualAcl = Get-Acl -LiteralPath $change.Path
        if (!(Test-RichOnlineSshHostKeyAcl -Acl $actualAcl)) {
            $actualSddl = $actualAcl.GetSecurityDescriptorSddlForm($ownerAndAccess)
            throw ('Host-key permission verification failed: ' + [IO.Path]::GetFileName($change.Path) + '; actual permissions: ' + $actualSddl)
        }
        if ((Get-FileHash -LiteralPath $change.Path -Algorithm SHA256).Hash -ne $change.Hash) {
            throw 'A host key changed during permission repair. Stop and review its identity before trusting this host.'
        }
        Write-Output ('Host-key permissions corrected: ' + [IO.Path]::GetFileName($change.Path))
    }
}
