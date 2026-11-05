@echo off
rem Builds Mute.exe (GUI) and Mute-cli.exe (console) into dist\
rem Run from anywhere; the script switches to the repository root.
cd /d "%~dp0.."
python -m pip install --require-hashes -r requirements.lock || goto :error
python -m pip install pyinstaller || goto :error

set OPTS=--onefile --hidden-import stem.control --hidden-import stem.process --hidden-import socks --collect-submodules noise --collect-all tkinterdnd2 --hidden-import sounddevice --hidden-import opuslib

python -m PyInstaller %OPTS% --windowed --icon assets\mute.ico --name Mute mute.py || goto :error
python -m PyInstaller %OPTS% --icon assets\mute.ico --name Mute-cli mute.py || goto :error

echo.
echo Done: dist\Mute.exe (GUI) and dist\Mute-cli.exe (terminal mode)
echo For Tor mode, put the Tor Expert Bundle's "tor" folder next to the .exe (see windows\README.md).
pause
exit /b 0

:error
echo Build failed.
pause
exit /b 1
