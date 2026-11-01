# Prints the full path of a tor.exe on this computer (Tor Browser install), or nothing.
$ErrorActionPreference = "SilentlyContinue"
$rel = "Tor Browser\Browser\TorBrowser\Tor\tor.exe"
$roots = @(
    [Environment]::GetFolderPath("Desktop"),
    (Join-Path $env:OneDrive "Desktop"),
    $env:LOCALAPPDATA, (Join-Path $env:LOCALAPPDATA "Programs"),
    $env:APPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)},
    $env:USERPROFILE, (Join-Path $env:USERPROFILE "Downloads")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
foreach ($r in $roots) {
    $p = Join-Path $r $rel
    if (Test-Path $p) { Write-Output $p; exit 0 }
}
# fall back to a shallow search for any Tor Browser folder
foreach ($r in $roots) {
    $hit = Get-ChildItem -Path $r -Directory -Filter "Tor Browser*" -Depth 2 | ForEach-Object {
        $c = Join-Path $_.FullName "Browser\TorBrowser\Tor\tor.exe"
        if (Test-Path $c) { $c }
    } | Select-Object -First 1
    if ($hit) { Write-Output $hit; exit 0 }
}
