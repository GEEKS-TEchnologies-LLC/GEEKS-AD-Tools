@echo off
REM GEEKS-AD-Plus Windows Build Script
REM This script automates the build process on Windows

setlocal enabledelayedexpansion

echo ========================================
echo GEEKS-AD-Plus Windows Build Script
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

echo Python found: 
python --version
echo.

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo pip found:
pip --version
echo.

REM Check if Visual Studio Build Tools are available
where msbuild >nul 2>&1
if errorlevel 1 (
    echo WARNING: MSBuild not found - credential provider will not be built
    echo To build the credential provider, install Visual Studio Build Tools
    echo.
) else (
    echo MSBuild found:
    where msbuild
    echo.
)

REM Run the Python build script
echo Starting build process...
echo.

python build.py %*

if errorlevel 1 (
    echo.
    echo Build failed! Check the build.log file for details
    pause
    exit /b 1
) else (
    echo.
    echo Build completed successfully!
    echo.
    echo Next steps:
    echo 1. Configure your Active Directory settings in config.json
    echo 2. Set up your environment variables in .env
    echo 3. Run the application: python app.py
    echo.
    pause
) 