@echo off
chcp 65001 >nul
cd /d "%~dp0"
cd "01_源代码"
if errorlevel 1 exit /b 1
if exist "D:\anaconda3\python.exe" (
  "D:\anaconda3\python.exe" main.py
) else (
  where py >nul 2>nul
  if errorlevel 1 (
    python main.py
  ) else (
    py -3 main.py
  )
)
if errorlevel 1 (
  echo 程序未能启动，请使用带 Tkinter 的 Python 3.10 或更高版本。
  pause
)
