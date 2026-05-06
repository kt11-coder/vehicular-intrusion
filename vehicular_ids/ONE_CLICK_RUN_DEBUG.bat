@echo off
cd /d "%~dp0"

set "PYTHON_SCRIPTS=%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts"
set "STREAMLIT_EXE=%PYTHON_SCRIPTS%\streamlit.exe"
set "STREAMLIT_HOME=%USERPROFILE%\.streamlit"
set "STREAMLIT_CREDENTIALS=%STREAMLIT_HOME%\credentials.toml"

set VEHICULAR_IDS_PUBLIC_DEMO=true
set STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

echo ==========================================
echo Vehicular IDS - Debug Launcher
echo ==========================================
echo Project folder: %cd%
echo Log file: logs\one_click_debug.log
echo.

if not exist logs mkdir logs
if not exist "%STREAMLIT_HOME%" mkdir "%STREAMLIT_HOME%"
if not exist "%STREAMLIT_CREDENTIALS%" (
    > "%STREAMLIT_CREDENTIALS%" echo [general]
    >> "%STREAMLIT_CREDENTIALS%" echo email = ""
)

echo Starting dashboard and saving output to logs\one_click_debug.log ...
echo If browser does not open, manually visit http://localhost:8501
echo.

start "" powershell -NoProfile -Command "Start-Sleep -Seconds 4; Start-Process 'http://localhost:8501'"
if exist "%STREAMLIT_EXE%" (
    "%STREAMLIT_EXE%" run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false --browser.gatherUsageStats false > "logs\one_click_debug.log" 2>&1
) else (
    python -m streamlit run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false --browser.gatherUsageStats false > "logs\one_click_debug.log" 2>&1
)

echo.
echo Dashboard stopped or failed.
echo Opening logs\one_click_debug.log ...
notepad "logs\one_click_debug.log"
pause
