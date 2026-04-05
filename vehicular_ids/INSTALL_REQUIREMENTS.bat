@echo off
cd /d "%~dp0"
echo Installing Vehicular IDS dependencies...
python -m pip install --upgrade pip
python -m pip install -r "requirements.txt"
echo.
echo Dependency installation finished.
pause
