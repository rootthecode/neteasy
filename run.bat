@echo off
rem One-click launcher: creates the virtualenv on first run, then starts NetEasy.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up NetEasy...
    python -m venv .venv || (echo Python 3.10+ is required. & pause & exit /b 1)
    ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
    ".venv\Scripts\python.exe" -m pip install --quiet -e .
)
start "" ".venv\Scripts\pythonw.exe" -m neteasy %*
