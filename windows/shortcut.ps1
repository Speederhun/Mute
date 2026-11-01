# Creates a "Mute" shortcut on the desktop that starts the app without a console window.
param([Parameter(Mandatory = $true)][string]$Root)
$pyw = Join-Path $Root ".venv\Scripts\pythonw.exe"
$desktop = [Environment]::GetFolderPath("Desktop")
$lnk = Join-Path $desktop "Mute.lnk"
$sh = New-Object -ComObject WScript.Shell
$s = $sh.CreateShortcut($lnk)
$s.TargetPath = $pyw
$s.Arguments = '"' + (Join-Path $Root "mute.py") + '"'
$s.WorkingDirectory = $Root
$s.Description = "Mute"
$ico = Join-Path $Root "assets\mute.ico"
if (Test-Path $ico) { $s.IconLocation = $ico }
$s.Save()
Write-Host "Shortcut created: $lnk"
