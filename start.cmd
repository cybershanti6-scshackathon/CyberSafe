@echo off
title CyberSure - Security Platform
color 0B
cls
echo.
echo ============================================
echo    CyberSure - Security Platform Launcher
echo ============================================
echo.

cd /d "%~dp0"

REM === Find Python ===
set "PYTHON="
where python >nul 2>&1
if %errorlevel% equ 0 (set "PYTHON=python"& goto :found)
where py >nul 2>&1
if %errorlevel% equ 0 (set "PYTHON=py"& goto :found)
where python3 >nul 2>&1
if %errorlevel% equ 0 (set "PYTHON=python3"& goto :found)

echo  ERROR: Python not found!
echo.
echo  Please install Python 3.10+ from https://python.org
echo  Make sure to check "Add Python to PATH" during install.
echo.
pause
exit /b 1

:found
echo  Python: %PYTHON%

REM === Check if launch.py exists ===
if not exist "launch.py" (
    echo.
    echo  ERROR: launch.py not found in %~dp0
    echo.
    pause
    exit /b 1
)

REM === Check dependencies ===
echo  Checking dependencies...
%PYTHON% -c "import fastapi, uvicorn, pydantic" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  Installing required packages...
    %PYTHON% -m pip install fastapi uvicorn pydantic httpx dnspython fpdf2 >nul 2>&1
    if %errorlevel% neq 0 (
        echo  WARNING: Some packages may not have installed correctly.
        echo  Try: pip install fastapi uvicorn pydantic httpx dnspython fpdf2
    ) else (
        echo  Dependencies installed successfully!
    )
)

echo.
echo  Starting CyberSure server...
echo.
echo ============================================
echo.
echo   Frontend:  http://localhost:8000
echo   Dashboard: http://localhost:8000/dashboard.html
echo   API Docs:  http://localhost:8000/docs
echo.
echo   Press Ctrl+C to stop
echo.
echo ============================================
echo.

REM Run the Python launcher
%PYTHON% launch.py

echo.
echo  Server stopped.
pause