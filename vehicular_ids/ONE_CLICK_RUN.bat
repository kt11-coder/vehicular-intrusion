@echo off
cd /d "%~dp0"

set "PYTHON_SCRIPTS=%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts"
set "STREAMLIT_EXE=%PYTHON_SCRIPTS%\streamlit.exe"
set "PIP_EXE=%PYTHON_SCRIPTS%\pip.exe"
set "STREAMLIT_HOME=%USERPROFILE%\.streamlit"
set "STREAMLIT_CREDENTIALS=%STREAMLIT_HOME%\credentials.toml"

echo ==========================================
echo Vehicular IDS - One Click Launcher
echo ==========================================
echo.

echo Checking Streamlit dependency...
if not exist "%STREAMLIT_EXE%" (
    echo Streamlit not found. Installing project dependencies...
    if exist "%PIP_EXE%" (
        "%PIP_EXE%" install --upgrade pip
        "%PIP_EXE%" install -r "requirements.txt"
    ) else (
        python -m pip install --upgrade pip
        python -m pip install -r "requirements.txt"
    )
    if errorlevel 1 (
        echo Dependency installation failed.
        pause
        exit /b 1
    )
)

if not exist "%STREAMLIT_HOME%" mkdir "%STREAMLIT_HOME%"
if not exist "%STREAMLIT_CREDENTIALS%" (
    > "%STREAMLIT_CREDENTIALS%" echo [general]
    >> "%STREAMLIT_CREDENTIALS%" echo email = ""
)

echo.
echo Starting Vehicular IDS Dashboard...
echo Opening http://localhost:8501 in your browser...
echo.

set VEHICULAR_IDS_PUBLIC_DEMO=true
set STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://localhost:8501'"
if exist "%STREAMLIT_EXE%" (
    "%STREAMLIT_EXE%" run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false --browser.gatherUsageStats false
) else (
    python -m streamlit run "app\dashboard.py" --server.address=127.0.0.1 --server.port=8501 --server.headless=false --browser.gatherUsageStats false
)
pause
