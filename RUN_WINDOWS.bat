@echo off
setlocal
cd /d "%~dp0"

echo ==========================================================
echo SecureMailScope - Complete SIH Prototype
echo ==========================================================

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Could not create virtual environment.
        echo Make sure Python 3.10+ is installed and available as "py".
        pause
        exit /b 1
    )
) else (
    echo [1/3] Virtual environment already exists.
)

echo [2/3] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r backend\requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo [3/3] Starting SecureMailScope...
echo Open http://127.0.0.1:5000
echo Press CTRL+C to stop.
".venv\Scripts\python.exe" backend\app.py

pause
