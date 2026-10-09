@echo off
setlocal
title AI DAST Dashboard Launcher

set "UI_WIN=%~dp0."
set "REPO_WIN=%~dp0.."

for /f "delims=" %%I in ('wsl.exe wslpath -a "%UI_WIN%"') do set "UI_WSL=%%I"
for /f "delims=" %%I in ('wsl.exe wslpath -a "%REPO_WIN%"') do set "REPO_WSL=%%I"

if not defined UI_WSL goto :path_error
if not defined REPO_WSL goto :path_error

start "AI DAST Dashboard Server" wsl.exe bash -lc "cd '%REPO_WSL%' && exec .venv/bin/aidast dashboard --ui-dir '%UI_WSL%/dist' --port 8000"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8000"
exit /b 0

:path_error
echo Failed to resolve the WSL paths for UI and AI DAST.
echo Expected WebUI to be inside the cloned AI DAST repository.
pause
exit /b 1
