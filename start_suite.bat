@echo off
setlocal
title ProctorGuard - Comprehensive Proctoring Suite
echo ======================================================================
echo              PROCTORGUARD - FULL PROCTORING TESTBED
echo ======================================================================
echo.

set "PATH=C:\Program Files\nodejs;%PATH%"

echo [*] Starting FastAPI Backend and Serving Web Portal...
python run_proctor_suite.py

pause
