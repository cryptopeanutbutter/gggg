@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: %~nx0 ^<build_folder^>
    exit /b 1
)

set BUILD_DIR=%~1
if not exist "%BUILD_DIR%" (
    echo Build directory not found: %BUILD_DIR%
    exit /b 1
)

set ZIP_NAME=%BUILD_DIR%_portable.zip
powershell -NoLogo -NoProfile -Command "Compress-Archive -Force -Path '%BUILD_DIR%\*' -DestinationPath '%ZIP_NAME%'"
if errorlevel 1 (
    echo Failed to create portable archive.
    exit /b 1
)

echo Portable package created: %ZIP_NAME%
exit /b 0
