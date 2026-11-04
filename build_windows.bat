@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo  NTP/NTS Diagnostic Tool - Windows Build (Rust)
echo ============================================================
echo.

where cargo >nul 2>&1
if errorlevel 1 (
    echo ERROR: Rust was not found. Install it from https://rustup.rs and re-run.
    pause
    exit /b 1
)

cargo test
if errorlevel 1 goto :fail

cargo build --release --locked
if errorlevel 1 goto :fail

if not exist "dist" mkdir "dist"
copy /y "target\release\NTP-NTS-Diagnostic-Tool.exe" "dist\" >nul || goto :fail
copy /y "target\release\ntpnts.exe" "dist\" >nul || goto :fail

echo.
echo ============================================================
echo  BUILD SUCCESSFUL
echo ============================================================
echo   %CD%\dist\NTP-NTS-Diagnostic-Tool.exe
echo   %CD%\dist\ntpnts.exe
pause
exit /b 0

:fail
echo.
echo ============================================================
echo  BUILD FAILED
echo ============================================================
pause
exit /b 1
