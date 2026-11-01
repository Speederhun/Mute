@echo off
rem Mute installer for Windows: installs Python if needed, sets up the app and puts a shortcut on the desktop.
rem Just double-click it. No administrator rights are needed.
setlocal
cd /d "%~dp0.."
set "PYEXE="

echo [1/5] Looking for Python 3.10 or newer...
call :findpython
if defined PYEXE goto :havepython

echo      Python not found - installing Python 3.12 for your user account...
where winget >nul 2>nul
if %errorlevel%==0 (
    winget install --id Python.Python.3.12 -e --scope user --silent --accept-package-agreements --accept-source-agreements
)
call :findpython
if defined PYEXE goto :havepython

echo      winget did not work, downloading the installer from python.org...
set "PYINST=%TEMP%\python-3.12.10-amd64.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe' -OutFile '%PYINST%'"
if not exist "%PYINST%" goto :nopython
"%PYINST%" /quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_launcher=0 Include_test=0
del "%PYINST%" >nul 2>nul
call :findpython
if defined PYEXE goto :havepython

:nopython
echo.
echo Could not install Python automatically. Please install it from https://www.python.org/downloads/windows/
echo (tick "Add python.exe to PATH") and run this file again.
pause
exit /b 1

:havepython
echo      Using: %PYEXE%

echo [2/5] Creating a private environment in .venv ...
"%PYEXE%" -m venv .venv || goto :error

echo [3/5] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --require-hashes -r requirements.lock
if errorlevel 1 (
    echo      Hash-checked install failed, trying the normal install...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error
)

echo [4/5] Creating the desktop shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0shortcut.ps1" -Root "%CD%"

echo [5/5] Looking for Tor (needed for TOR mode)...
call :findtor
if defined TOREXE goto :havetor
where winget >nul 2>nul
if %errorlevel%==0 (
    echo      Tor not found - installing Tor Browser via winget - Mute uses its tor.exe ...
    winget install --id TorProject.TorBrowser -e --silent --accept-package-agreements --accept-source-agreements
    call :findtor
)
if defined TOREXE goto :havetor
echo      Could not set up Tor automatically. DIRECT mode works without it.
echo      For TOR mode install Tor Browser from https://www.torproject.org/download/ and run this file again.
goto :finish

:havetor
echo      Using Tor: %TOREXE%
rem the path is written by PowerShell as UTF-8 (cmd would mangle folder names with accents)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0find-tor.ps1" -Out "%CD%\tor_path.txt" >nul

:finish
echo.
echo Done. Start Mute from the "Mute" icon on your desktop.
pause
exit /b 0

:error
echo.
echo Something went wrong - see the messages above.
pause
exit /b 1

rem ---- sets PYEXE to a Python 3.10+ that has Tkinter, or leaves it empty
:findpython
set "PYEXE="
for %%P in ("%LOCALAPPDATA%\Programs\Python\Python313\python.exe" "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" "%LOCALAPPDATA%\Programs\Python\Python310\python.exe") do (
    if not defined PYEXE if exist %%P (
        %%P -c "import sys,tkinter; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
        if not errorlevel 1 set "PYEXE=%%~P"
    )
)
if defined PYEXE exit /b 0
where py >nul 2>nul
if %errorlevel%==0 (
    for /f "delims=" %%I in ('py -3 -c "import sys,tkinter; assert sys.version_info>=(3,10); print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
)
if defined PYEXE exit /b 0
for /f "delims=" %%I in ('python -c "import sys,tkinter; assert sys.version_info>=(3,10); print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
exit /b 0

rem ---- sets TOREXE to a tor.exe found on this computer (empty if none)
:findtor
set "TOREXE="
for /f "delims=" %%I in ('powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0find-tor.ps1"') do set "TOREXE=%%I"
exit /b 0
