@echo off
cd /d "%~dp0"
echo Running Vehicular IDS CLI pipeline...
python "main.py" --alerts-output "reports\alerts_v2.csv" --db-path "storage\vehicular_ids.sqlite3"
pause
