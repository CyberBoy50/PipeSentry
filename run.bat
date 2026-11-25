@echo off
REM PipeSentry - one click to open the menu (Windows)
cd /d "%~dp0"
python run.py scan %*
pause
