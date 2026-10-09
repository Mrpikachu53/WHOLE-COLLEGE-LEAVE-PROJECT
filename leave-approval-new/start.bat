@echo off
setlocal
cd /d "%~dp0"
REM Always use this project's local database and saved invitation configuration.
set APP_ENV=development
set DATABASE_URL=
set ADMIN_ACCESS_KEY=
set FACULTY_SIGNUP_CODE=
set PUBLIC_URL=
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  if errorlevel 1 goto failed
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed
.venv\Scripts\python.exe setup_app.py
if errorlevel 1 goto failed
echo.
echo Open http://127.0.0.1:8002 in your browser after startup completes.
echo Keep this window open. Press Ctrl+C to stop the website.
.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8002
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Startup failed. Read the error above or send a screenshot of it.
pause
exit /b 1
