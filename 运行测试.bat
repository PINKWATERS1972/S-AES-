@echo off
chcp 65001 >nul
cd /d "%~dp0"
cd "01_源代码"
if errorlevel 1 exit /b 1
if exist "D:\anaconda3\python.exe" (
  "D:\anaconda3\python.exe" verify.py
) else (
  where py >nul 2>nul
  if errorlevel 1 (
    python verify.py
  ) else (
    py -3 verify.py
  )
)
pause
