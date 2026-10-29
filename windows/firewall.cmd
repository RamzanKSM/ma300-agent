@echo off
rem MA300 agent: allow inbound UDP from MA300_HOST in Windows Firewall.
rem   firewall.cmd          create or refresh the rule
rem   firewall.cmd /remove  delete the rule
rem Double-click is enough: without administrator rights the script asks
rem Windows for them (UAC) once and runs itself again in a new window with
rem the extra flag /elevated. That copy never asks again, so windows cannot
rem cascade. /nopause is used by install.cmd and uninstall.cmd.
setlocal
set "HELPER=%~dp0ma300_setup.py"
set "PYEXE=%~dp0..\.venv\Scripts\python.exe"
set "MODE="
set "ELEVATED="
set "NOPAUSE="

:args
if "%~1"=="" goto args_done
if /i "%~1"=="/remove" set "MODE=/remove"
if /i "%~1"=="/elevated" set "ELEVATED=1"
if /i "%~1"=="/nopause" set "NOPAUSE=1"
shift
goto args
:args_done

if not exist "%PYEXE%" (
    echo The agent is not installed yet: run windows\install.cmd first.
    set "RC=1"
    goto end
)
"%PYEXE%" "%HELPER%" firewall %MODE%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="5" goto end
if defined ELEVATED goto still_not_admin

echo.
echo Asking Windows for administrator rights, a new window will open...
set "MA300_FIREWALL_CMD=%~f0"
set "MA300_FIREWALL_ARGS=%MODE% /elevated"
powershell -NoProfile -Command "Start-Process -FilePath $env:MA300_FIREWALL_CMD -ArgumentList $env:MA300_FIREWALL_ARGS -Verb RunAs"
if errorlevel 1 goto refused
echo The firewall rule is changed in the new window - read the result there.
set "RC=0"
goto end

:refused
echo Administrator rights were not granted: the firewall rule was not changed.
set "RC=1"
goto end

:still_not_admin
echo Windows started this window without administrator rights, so the rule was
echo not changed. Sign in with an administrator account, or ask the administrator
echo to run windows\firewall.cmd %MODE% for you.
set "RC=1"

:end
if defined NOPAUSE exit /b %RC%
echo.
pause
exit /b %RC%
