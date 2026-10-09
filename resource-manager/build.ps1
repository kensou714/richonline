param([switch]$Publish)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
  & clang++ -shared -O2 -static -std=c++17 native/bridge.cpp ../server/vendor/lzokay/lzokay.cpp -o native/ResourceCodec.dll
  if ($LASTEXITCODE -ne 0) { throw '资源解码组件编译失败' }
  & dotnet build -c Release
  if ($LASTEXITCODE -ne 0) { throw '资源管理器编译失败' }
  if ($Publish) {
    & dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
    if ($LASTEXITCODE -ne 0) { throw '发布失败' }
    Copy-Item -LiteralPath 'publish/RichOnline.Resources.exe' -Destination '../RichOnline.Resources.exe' -Force
    Copy-Item -LiteralPath 'native/ResourceCodec.dll' -Destination '../ResourceCodec.dll' -Force
    Copy-Item -LiteralPath '../server/vendor/lzokay/LICENSE' -Destination '../ResourceCodec.LICENSE.txt' -Force
  }
} finally { Pop-Location }
