@echo off
cd /d "%~dp0"
echo Starting Vehicular IDS Dashboard...
python -m streamlit run "app\dashboard.py"
pause
