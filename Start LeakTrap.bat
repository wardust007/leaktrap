@echo off
title LeakTrap Dashboard
cd /d "%~dp0"
echo.
echo   Starting LeakTrap... your browser will open in a moment.
echo   To stop, close this window.
echo.
python -m leaktrap ui 2>nul
if errorlevel 1 py -m leaktrap ui
if errorlevel 1 (
  echo.
  echo   Could not start LeakTrap.
  echo   1. Install Python from https://www.python.org/downloads/
  echo   2. Tick "Add python.exe to PATH" in the installer, then double-click this file again.
  echo.
  pause
)
