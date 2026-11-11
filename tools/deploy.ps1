# Empaquette le lanceur, l'installe sur la TV et le démarre.
$ErrorActionPreference = 'Stop'
$root  = Split-Path $PSScriptRoot -Parent
$sdb   = 'C:\Users\theor\tizen-studio\tools\sdb.exe'
$tizen = 'C:\Users\theor\tizen-studio\tools\ide\bin\tizen.bat'
$build = Join-Path $root 'build'
$appId = 'MonAccueil.Launcher'
$remote = '/home/owner/share/tmp/sdk_tools/tmp/MonAccueil.wgt'

New-Item -ItemType Directory -Force $build | Out-Null
Get-ChildItem $build -Filter *.wgt | Remove-Item
& $tizen package -t wgt -s MonAccueil -o $build -- (Join-Path $root 'launcher') | Select-Object -Last 1
$wgt = Get-ChildItem $build -Filter *.wgt | Select-Object -First 1
& $sdb push $wgt.FullName $remote | Select-Object -Last 1
& $sdb shell 0 vd_appinstall $appId $remote | Select-Object -Last 3
& $sdb shell 0 was_execute $appId
