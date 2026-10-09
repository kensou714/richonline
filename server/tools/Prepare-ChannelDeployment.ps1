param([Parameter(Mandatory = $true)][string]$Workspace)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Workspace).Path
$live = Join-Path $root 'local-server/runtime/native-boss-live-20261009'
$source = Join-Path $PSScriptRoot '../build/RichOnline.Server.exe'
$target = Join-Path $live 'RichOnline.Server.channels.exe'
if (Get-Process -Name 'RichOnline.Server.channels' -ErrorAction SilentlyContinue) { throw 'candidate_server_is_running' }
$config = [IO.File]::ReadAllText((Join-Path $live 'lobby-bootstrap.json')) | ConvertFrom-Json -AsHashtable
$names = @('初級頻道', '高級頻道', '競技頻道')
$config.channels = @(for ($index = 0; $index -lt 3; $index++) {
    @{
        key = $index; name_utf8 = $names[$index]; room_capacity = $config.game_capacity
        player_capacity = $config.player_capacity; lobby_type = $index; status = 1
        min_gold = 0; max_gold = 999999999; min_level = 0; max_level = 999
        wire_record_hex = $config.unknown_channel_record_hex
    }
})
$config.policy_notes.channels = 'Explicit local open-channel policy: CHU=initial, ZHONG=advanced, GAO=competitive; labels proven from NEW UI resources. Shared HTTP/wire catalog and room/game identity use keys 0/1/2. Broad level and gold ranges are operator policy, not official recovered limits.'
$config.richonline_boss_game.provenance = 'Native single-human BS_1_1 with real client startup verified; resource-based ordinary purchases, point and single-card landings. Other game events and special BOSS gameplay remain incomplete.'
[IO.File]::WriteAllText((Join-Path $live 'lobby-bootstrap.channels.json'), ($config | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $source -Destination $target
[pscustomobject]@{server=$target; sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash; config='lobby-bootstrap.channels.json'} | ConvertTo-Json -Compress
