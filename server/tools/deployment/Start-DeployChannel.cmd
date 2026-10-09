@echo off
setlocal
title RichOnline Deployment Connection Setup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DeployChannel.ps1"
set "richonlineResult=%ERRORLEVEL%"
echo.
echo Result code: %richonlineResult%
echo Report file: %~dp0deploy-diagnostics.txt
echo Keep all package files together. Run this file on the destination server.
pause
exit /b %richonlineResult%
