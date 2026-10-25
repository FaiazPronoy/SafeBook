@echo off
setlocal
title SafeBook
cd /d "%~dp0"

echo ==========================================
echo   SAFEBOOK
echo ==========================================
echo.

REM  1. A Python the pinned packages install on. "py" finds a python.org
REM     install first, which is what we want.
set "PY="
for %%V in (3.12 3.11 3.13) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1
    if not errorlevel 1 set "PY=py -%%V"
  )
)
if not defined PY (
  python -c "import sys" >nul 2>&1
  if not errorlevel 1 set "PY=python"
)
if not defined PY (
  echo [X] No Python found. Install Python 3.12 from python.org and tick
  echo     "Add python.exe to PATH" on the first installer screen.
  pause
  exit /b 1
)

set "VPY=%CD%\.venv\Scripts\python.exe"
if not exist "%VPY%" (
  echo [1/5] Creating the virtual environment ...
  %PY% -m venv .venv
) else (
  echo [1/5] Virtual environment ready.
)

echo [2/5] Installing packages ...
"%VPY%" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo [X] The packages would not install. Run this by hand to see why:
  echo         "%VPY%" -m pip install -r requirements.txt
  pause
  exit /b 1
)

REM  2. Keys. A new .env gets a fresh SECRET_KEY and server key; an existing
REM     one is left exactly as it is, because its key opens the public posts.
if not exist ".env" (
  echo [3/5] Writing .env with fresh keys ...
  copy /y ".env.example" ".env" >nul
  "%VPY%" manage.py new_keys --write
) else (
  echo [3/5] .env already there.
)

echo [4/5] Preparing the database ...
"%VPY%" manage.py migrate --noinput
"%VPY%" manage.py seed_demo

echo [5/5] Starting SafeBook at http://127.0.0.1:8010
echo.
echo   Demo people are on the sign in page: pick a card, nothing to type.
echo   Close this window to stop SafeBook.
echo.
start "" http://127.0.0.1:8010
"%VPY%" manage.py runserver 127.0.0.1:8010
pause
