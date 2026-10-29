@echo off
rem MA300 agent: remove the logon autostart, stop the agent and delete the
rem firewall rule created by "install.cmd /firewall" (that needs Administrator).
rem .env, logs and .venv stay in the agent folder.
setlocal
set "HELPER=%~dp0ma300_setup.py"
set "PYEXE=%~dp0..\.venv\Scripts\python.exe"
set "PYARGS="
if exist "%PYEXE%" goto run
set "PYEXE=py"
set "PYARGS=-3"
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 goto run
set "PYEXE=python"
set "PYARGS="
python -c "import sys" >nul 2>&1
if not errorlevel 1 goto run
echo Python was not found: tried .venv, "py -3" and "python".
set "RC=1"
goto end

:run
"%PYEXE%" %PYARGS% "%HELPER%" uninstall %*
set "RC=%ERRORLEVEL%"
rem 5: removed, but the firewall rule needs administrator rights to go.
if not "%RC%"=="5" goto end
call "%~dp0firewall.cmd" /remove /nopause
set "RC=%ERRORLEVEL%"

:end
echo.
pause
exit /b %RC%
