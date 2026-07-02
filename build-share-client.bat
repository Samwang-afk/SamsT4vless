@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0package-client.ps1"
if errorlevel 1 pause
