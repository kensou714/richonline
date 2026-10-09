@echo off
setlocal
title RichOnline SSH Host Key Permission Repair
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DeployChannel.ps1" -RepairHostKeys
set "richonlineResult=%ERRORLEVEL%"
echo.
echo Result code: %richonlineResult%
echo Report file: %~dp0deploy-diagnostics.txt
pause
exit /b %richonlineResult%
