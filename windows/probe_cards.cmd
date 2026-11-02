@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo Stopping the MA300 agent for two minutes...
schtasks /end /tn "MA300 Agent" >nul 2>&1
timeout /t 3 /nobreak >nul
.venv\Scripts\python.exe probe_card_events.py
echo Starting the MA300 agent again...
schtasks /run /tn "MA300 Agent"
pause
