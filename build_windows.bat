@echo off
rem Tedd a tor.exe-t (Tor Expert Bundle) a "tor" mappaba az .exe mellé, ha Tor módot akarsz.
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --windowed --name Mute --hidden-import stem.control --hidden-import stem.process --hidden-import socks mute.py
echo Kesz: dist\Mute.exe
pause
