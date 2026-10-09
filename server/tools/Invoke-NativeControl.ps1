param(
    [Parameter(Mandatory = $true)][string]$PipeName,
    [ValidateSet('status', 'config.get', 'database.backup', 'stop')][string]$Command = 'status',
    [string]$ExpectedInstance = ''
)
$ErrorActionPreference = 'Stop'

function Invoke-ControlRequest([string]$Operation) {
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try {
        $pipe.Connect(5000)
        $requestId = [Guid]::NewGuid().ToString('N')
        $request = @{version=1; requestId=$requestId; command=$Operation; payload=@{}} | ConvertTo-Json -Compress
        $body = [Text.Encoding]::UTF8.GetBytes($request)
        $header = [BitConverter]::GetBytes([uint32]$body.Length)
        foreach ($part in @($header, $body)) {
            $write = $pipe.WriteAsync($part, 0, $part.Length)
            if (-not $write.Wait([Math]::Max(0, 5000 - [int]$elapsed.ElapsedMilliseconds))) { throw 'control_write_timeout' }
            $write.GetAwaiter().GetResult()
        }
        $length = 4
        $reply = $null
        for ($framePart = 0; $framePart -lt 2; $framePart++) {
            $buffer = [byte[]]::new($length)
            $offset = 0
            while ($offset -lt $length) {
                $read = $pipe.ReadAsync($buffer, $offset, $length - $offset)
                if (-not $read.Wait([Math]::Max(0, 5000 - [int]$elapsed.ElapsedMilliseconds))) { throw 'control_read_timeout' }
                $count = $read.GetAwaiter().GetResult()
                if ($count -eq 0) { throw 'control_peer_closed' }
                $offset += $count
            }
            if ($framePart -eq 0) {
                $length = [BitConverter]::ToUInt32($buffer, 0)
                if ($length -lt 1 -or $length -gt 65536) { throw 'control_frame_length_invalid' }
            } else { $reply = [Text.Encoding]::UTF8.GetString($buffer) | ConvertFrom-Json }
        }
        if ($reply.version -ne 1 -or $reply.requestId -ne $requestId) { throw 'control_response_mismatch' }
        if ($reply.ok -ne $true) { throw [string]$reply.error.code }
        return $reply.result
    } finally { $pipe.Dispose() }
}

if ($Command -eq 'stop') {
    if ([string]::IsNullOrEmpty($ExpectedInstance)) { throw 'stop_expected_instance_required' }
    $current = Invoke-ControlRequest 'status'
    if ($current.instanceId -ne $ExpectedInstance) { throw 'stop_instance_mismatch' }
    if ($null -eq $current.authenticatedSessions -or $current.authenticatedSessions -ne 0) {
        throw 'stop_requires_zero_authenticated_sessions'
    }
}
Invoke-ControlRequest $Command | ConvertTo-Json -Depth 16
