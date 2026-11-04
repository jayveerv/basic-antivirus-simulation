@echo off
setlocal
cd /d "%~dp0"
title Basic Antivirus Simulation

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)

if not exist .venv (
  echo Creating a virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -q --disable-pip-version-check -r requirements-dev.txt

:menu
echo.
echo  ==== Basic Antivirus Simulation ====
echo   1. Open the web app (http://127.0.0.1:5000)
echo   2. Create safe sample files and run a full scan
echo   3. Quick scan of a folder
echo   4. Real-time monitor (folder "watched")
echo   5. Show quarantine
echo   6. Show scan history
echo   7. Run unit tests
echo   0. Exit
set /p c=Choose: 
if "%c%"=="1" start "" http://127.0.0.1:5000 & python webapp\app.py & goto menu
if "%c%"=="2" python scan.py samples demo_files & python scan.py scan demo_files --report both --quarantine & goto menu
if "%c%"=="3" set /p f=Folder to scan: & call python scan.py scan "%%f%%" --quick & goto menu
if "%c%"=="4" python scan.py watch watched --quarantine & goto menu
if "%c%"=="5" python scan.py quarantine list & goto menu
if "%c%"=="6" python scan.py history & goto menu
if "%c%"=="7" python -m pytest -q & goto menu
if "%c%"=="0" exit /b 0
goto menu
