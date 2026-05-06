@echo off
cd /d "%~dp0"
set "PYTHON_SCRIPTS=%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts"
set "STREAMLIT_EXE=%PYTHON_SCRIPTS%\streamlit.exe"
set "STREAMLIT_HOME=%USERPROFILE%\.streamlit"
set "STREAMLIT_CREDENTIALS=%STREAMLIT_HOME%\credentials.toml"
set STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
if not exist "%STREAMLIT_HOME%" mkdir "%STREAMLIT_HOME%"
if not exist "%STREAMLIT_CREDENTIALS%" (
    > "%STREAMLIT_CREDENTIALS%" echo [general]
    >> "%STREAMLIT_CREDENTIALS%" echo email = ""
)
echo Starting Vehicular IDS Dashboard...
if exist "%STREAMLIT_EXE%" (
    "%STREAMLIT_EXE%" run "app\dashboard.py" --browser.gatherUsageStats false
) else (
    python -m streamlit run "app\dashboard.py" --browser.gatherUsageStats false
)
pause
