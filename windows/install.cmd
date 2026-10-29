@echo off
rem MA300 agent: install autostart at Windows logon for the current user.
rem Usage: install.cmd [C:\path\to\python.exe] [/firewall] [/user:PC\name]
rem   /firewall   also allow inbound UDP from MA300_HOST (asks for administrator rights).
rem   /user:...   start the agent at logon of this account instead of the console user.
setlocal
set "HELPER=%~dp0ma300_setup.py"
set "PYEXE="
set "PYARGS="
set "FIRST=%~1"
if not defined FIRST goto find
if "%FIRST:~0,1%"=="/" goto find
set "PYEXE=%~1"
goto run

:find
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PYEXE=py"
    set "PYARGS=-3"
    goto run
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PYEXE=python"
    goto run
)
echo Python 3.8 or newer was not found: tried "py -3" and "python".
echo Install Python 3.8 or pass its path: install.cmd C:\Python38\python.exe
set "RC=1"
goto end

:run
"%PYEXE%" %PYARGS% "%HELPER%" install %*
set "RC=%ERRORLEVEL%"
rem 5: installed, "/firewall" still needs administrator rights.
rem 6: the same, but /healthz did not answer either (stays an error).
if "%RC%"=="5" goto firewall
if "%RC%"=="6" goto firewall
goto end

:firewall
set "WAS=%RC%"
call "%~dp0firewall.cmd" /nopause
set "RC=%ERRORLEVEL%"
if "%WAS%"=="6" set "RC=1"

:end
echo.
pause
exit /b %RC%
