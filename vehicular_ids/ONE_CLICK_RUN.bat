@echo off
cd /d "%~dp0"

echo ==========================================
echo Vehicular IDS - One Click Launcher
echo ==========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found on this system.
    echo Please install Python 3.11+ and try again.
    pause
    exit /b 1
)

echo Checking Streamlit dependency...
python -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo Streamlit not found. Installing project dependencies...
    python -m pip install --upgrade pip
    python -m pip install -r "requirements.txt"
    if errorlevel 1 (
        echo Dependency installation failed.
        pause
        exit /b 1
    )
)

echo.
echo Starting Vehicular IDS Dashboard...
echo Opening http://localhost:8501 in your browser...
echo.

set VEHICULAR_IDS_PUBLIC_DEMO=true
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://localhost:8501'"
python -m streamlit run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false
pause
