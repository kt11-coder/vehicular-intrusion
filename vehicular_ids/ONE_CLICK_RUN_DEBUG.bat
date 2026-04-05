@echo off
cd /d "%~dp0"

set VEHICULAR_IDS_PUBLIC_DEMO=true

echo ==========================================
echo Vehicular IDS - Debug Launcher
echo ==========================================
echo Project folder: %cd%
echo Log file: logs\one_click_debug.log
echo.

if not exist logs mkdir logs

echo Starting dashboard and saving output to logs\one_click_debug.log ...
echo If browser does not open, manually visit http://localhost:8501
echo.

start "" powershell -NoProfile -Command "Start-Sleep -Seconds 4; Start-Process 'http://localhost:8501'"
python -m streamlit run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false > "logs\one_click_debug.log" 2>&1

echo.
echo Dashboard stopped or failed.
echo Opening logs\one_click_debug.log ...
notepad "logs\one_click_debug.log"
pause
