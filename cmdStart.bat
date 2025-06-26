@echo off
setlocal

:: Get the directory where this batch file is located
set "batch_dir=%~dp0"

:: Change to the directory containing the batch file
cd /d "%batch_dir%"

:: Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Run the server_ui.py script
python server_ui.py

:: Keep the console window open after execution
pause