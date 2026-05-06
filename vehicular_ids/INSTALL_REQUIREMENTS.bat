@echo off
cd /d "%~dp0"
set "PYTHON_SCRIPTS=%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts"
set "PIP_EXE=%PYTHON_SCRIPTS%\pip.exe"
echo Installing Vehicular IDS dependencies...
if exist "%PIP_EXE%" (
    "%PIP_EXE%" install --upgrade pip
    "%PIP_EXE%" install -r "requirements.txt"
) else (
    python -m pip install --upgrade pip
    python -m pip install -r "requirements.txt"
)
echo.
echo Dependency installation finished.
pause
