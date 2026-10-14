@echo off
title SOAR Sentinel
cd /d "%~dp0"

rem --- Use the local virtual environment if it exists ---
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

rem --- Make sure Flask is installed ---
"%PY%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    "%PY%" -m pip install -r requirements.txt
)

rem --- Open the browser now; it will load once the server is up ---
start "" http://127.0.0.1:5000
echo Starting SOAR Sentinel at http://127.0.0.1:5000
echo Close this window or press Ctrl+C to stop the server.
echo.

rem --- Run the server (blocks until you stop it) ---
"%PY%" app.py
pause