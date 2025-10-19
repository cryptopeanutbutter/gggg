@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
for %%i in ("%SCRIPT_DIR%..") do set ROOT_DIR=%%~fi
set LOG_FILE=%SCRIPT_DIR%install.log

if not exist "%LOG_FILE%" (
    type nul > "%LOG_FILE%"
)

call :log "Invocation with args: %*"

set FORCE=0
set ELEVATE=0
for %%I in (%*) do (
    if /I "%%~I"=="--force" set FORCE=1
    if /I "%%~I"=="--elevate" set ELEVATE=1
)

call :header
set /p CONFIRM=Proceed with WHOIS Watching build and install? (Y/N): 
if /I not "%CONFIRM%"=="Y" (
    echo Aborted by user.
    call :log "User declined to proceed."
    exit /b 0
)

pushd "%ROOT_DIR%" || goto :error_pushd

where python >nul 2>&1
if errorlevel 1 goto :error_python

if not exist "%ROOT_DIR%\venv\Scripts\python.exe" (
    echo Creating virtual environment...
    call :log "Creating virtual environment"
    python -m venv "%ROOT_DIR%\venv"
    if errorlevel 1 goto :error_venv
)

call "%ROOT_DIR%\venv\Scripts\activate.bat"
if errorlevel 1 goto :error_activate

python -m pip install --upgrade pip
if errorlevel 1 goto :error_pip

python -m pip install -r requirements.txt
if errorlevel 1 goto :error_requirements

pytest
if errorlevel 1 (
    if "%FORCE%"=="1" (
        echo Tests failed, continuing due to --force.
        call :log "Tests failed but continuing due to --force"
    ) else (
        call :log "Tests failed. Aborting build."
        echo Tests failed. Re-run with --force to override.
        exit /b 1
    )
)

for /f %%i in ('powershell -NoLogo -NoProfile -Command "Get-Date -Format yyyyMMddHHmmss"') do set BUILD_ID=%%i
set VERSION=1.0.0
set BUILD_ROOT=%ROOT_DIR%\compiled\WHOIS_Watching-%VERSION%-win64-%BUILD_ID%
set BUILD_ONEFILE=%BUILD_ROOT%\onefile
set BUILD_ONEDIR=%BUILD_ROOT%\onedir

if exist "%BUILD_ROOT%" rd /s /q "%BUILD_ROOT%"
mkdir "%BUILD_ONEFILE%"
mkdir "%BUILD_ONEDIR%"

set VERSION_FILE=%SCRIPT_DIR%version_%BUILD_ID%.txt
powershell -NoLogo -NoProfile -Command "param($path,$buildId) $content = @'
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'WHOIS Watching Project'),
        StringStruct('FileDescription', 'WHOIS Watching'),
        StringStruct('FileVersion', '1.0.0'),
        StringStruct('ProductVersion', '1.0.0'),
        StringStruct('OriginalFilename', 'WHOIS_Watching.exe'),
        StringStruct('ProductName', 'WHOIS Watching'),
        StringStruct('BuildID', '{BUILD_ID}')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
'@; $content = $content -replace '{BUILD_ID}', $buildId; Set-Content -Path $path -Value $content -Encoding UTF8" "%VERSION_FILE%" "%BUILD_ID%"
if errorlevel 1 goto :error_versionfile

set WHOIS_WATCHING_VERSION_FILE=%VERSION_FILE%

pyinstaller --noconfirm --clean --log-level=WARN --distpath "%BUILD_ONEDIR%" --workpath "%ROOT_DIR%\build\onedir_%BUILD_ID%" --specpath "%ROOT_DIR%\build\onedir_%BUILD_ID%" "%ROOT_DIR%\scripts\whois_watching.spec"
if errorlevel 1 goto :error_pyinstaller

pyinstaller --noconfirm --clean --log-level=WARN --onefile --name WHOIS_Watching --distpath "%BUILD_ONEFILE%" --workpath "%ROOT_DIR%\build\onefile_%BUILD_ID%" --specpath "%ROOT_DIR%\build\onefile_%BUILD_ID%" --add-data "assets\logo.svg;assets" --add-data "assets\starfield.svg;assets" --add-data "data\mock_processes.json;data" main.py
if errorlevel 1 goto :error_pyinstaller

set EXE_PATH=%BUILD_ONEFILE%\WHOIS_Watching.exe
if not exist "%EXE_PATH%" goto :error_missing_exe

for /f %%h in ('powershell -NoLogo -NoProfile -Command "Get-FileHash -Algorithm SHA256 -Path '%EXE_PATH%' | Select-Object -ExpandProperty Hash"') do set EXE_SHA=%%h
call :log "Built executable SHA256: %EXE_SHA%"
echo SHA256 (onefile exe): %EXE_SHA%

set INSTALLER_PATH=

set /p INSTALLER_PROMPT=Build Windows setup installer (requires Inno Setup ISCC.exe)? (Y/N):
if /I "%INSTALLER_PROMPT%"=="Y" call :build_installer

set /p ZIP_CHOICE=Create portable ZIP package? (Y/N):
if /I "%ZIP_CHOICE%"=="Y" (
    call "%SCRIPT_DIR%create_portable_zip.bat" "%BUILD_ROOT%"
)

set MANIFEST_EXTRA=
if defined INSTALLER_PATH (
    set MANIFEST_EXTRA=, 'installer': str(Path(r'%INSTALLER_PATH%'))
)
python -c "from pathlib import Path; import sys; from utils import build_manifest; requirements = Path('requirements.txt').read_text(encoding='utf-8').splitlines(); manifest_path = Path(r'%BUILD_ROOT%') / 'build_manifest.json'; build_manifest.create_manifest(manifest_path, version='%VERSION%', build_id='%BUILD_ID%', python_version=sys.version.split()[0], dependencies=requirements, artifacts={'onefile': str(Path(r'%BUILD_ONEFILE%') / 'WHOIS_Watching.exe'), 'onedir': str(Path(r'%BUILD_ONEDIR%') / 'WHOIS_Watching' / 'WHOIS_Watching.exe')%MANIFEST_EXTRA%})"
if errorlevel 1 goto :error_manifest

echo Build artifacts available in %BUILD_ROOT%
call :log "Build completed: %BUILD_ROOT%"

set /p INSTALL_CHOICE=Perform user-level install to %%LOCALAPPDATA%%\Programs\WHOIS_Watching\ ? (Y/N):
if /I "%INSTALL_CHOICE%"=="Y" goto :user_install

set /p SYSTEM_CHOICE=Generate system-wide install script for C:\\Program Files\\WHOIS_Watching\\ ? (Y/N):
if /I "%SYSTEM_CHOICE%"=="Y" goto :system_install

goto :cleanup

:build_installer
call :log "Installer build requested"
where iscc >nul 2>&1
if errorlevel 1 (
    echo Inno Setup ISCC.exe not found in PATH. Skipping installer build.
    call :log "ISCC.exe missing - skipping installer build"
    goto :after_installer
)
set INSTALLER_SOURCE=%BUILD_ONEDIR%\WHOIS_Watching
if not exist "%INSTALLER_SOURCE%" (
    echo PyInstaller onedir output missing at %INSTALLER_SOURCE%.
    call :log "Onedir bundle missing for installer"
    goto :after_installer
)
set INSTALLER_NAME=WHOIS_Watching_Setup_%VERSION%_%BUILD_ID%.exe
call :log "Running ISCC.exe to build installer %INSTALLER_NAME%"
iscc "%SCRIPT_DIR%whois_watching_installer.iss" /DAppVersion=%VERSION% /DAppBuild=%BUILD_ID% /DSourceDir=%INSTALLER_SOURCE% /DOutputDir=%BUILD_ROOT%
if errorlevel 1 goto :error_installer
set INSTALLER_PATH=%BUILD_ROOT%\WHOIS_Watching_Setup_%VERSION%_%BUILD_ID%.exe
if not exist "%INSTALLER_PATH%" (
    echo Installer output not found at %INSTALLER_PATH%.
    call :log "Installer output missing after ISCC"
    goto :after_installer
)
echo Installer created at %INSTALLER_PATH%
call :log "Installer created: %INSTALLER_PATH%"

:after_installer
exit /b 0

:user_install
if "%LOCALAPPDATA%"=="" (
    echo LOCALAPPDATA not defined. Cannot perform user-level install.
    goto :cleanup
)
set DEST=%LOCALAPPDATA%\Programs\WHOIS_Watching
call :log "User-level install to %DEST%"
if exist "%DEST%" rd /s /q "%DEST%"
mkdir "%DEST%"
xcopy "%BUILD_ROOT%" "%DEST%" /E /I /Y >nul
for /f "delims=" %%p in ('powershell -NoLogo -NoProfile -Command "[Environment]::GetFolderPath('StartMenu')"') do set STARTMENU=%%p
set SHORTCUT=%STARTMENU%\Programs\WHOIS Watching.lnk
powershell -NoLogo -NoProfile -Command "param($shortcut,$target) $shell = New-Object -ComObject WScript.Shell; $link = $shell.CreateShortcut($shortcut); $link.TargetPath = $target; $link.IconLocation = $target; $link.WorkingDirectory = (Split-Path $target); $link.Save()" "%SHORTCUT%" "%BUILD_ONEFILE%\WHOIS_Watching.exe"
echo Installed to %DEST%
call :log "User-level install completed"
goto :cleanup

:system_install
echo System-wide install requires elevation. No actions taken.
if not "%ELEVATE%"=="1" (
    echo Re-run with --elevate and manual elevation to proceed.
    call :log "System install requested without --elevate"
    goto :cleanup
)
set PS_SCRIPT=%SCRIPT_DIR%install_system_%BUILD_ID%.ps1
powershell -NoLogo -NoProfile -Command "param($path,$build,$source) $content = @'
param()
Write-Host 'WHOIS Watching system install requires elevation.'
$destination = 'C:\\Program Files\\WHOIS_Watching'
if (Test-Path $destination) { Remove-Item -Recurse -Force $destination }
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force -Path $source -Destination $destination
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\\WHOIS Watching.lnk'
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = Join-Path $destination 'onefile/WHOIS_Watching.exe'
$link.IconLocation = $link.TargetPath
$link.WorkingDirectory = $destination
$link.Save()
Write-Host 'System-wide install complete.'
'@; Set-Content -Path $path -Value $content -Encoding UTF8" "%PS_SCRIPT%" "%BUILD_ID%" "%BUILD_ROOT%"
echo Generated elevation script: %PS_SCRIPT%
call :log "System install script generated: %PS_SCRIPT%"
goto :cleanup

:cleanup
if exist "%VERSION_FILE%" del "%VERSION_FILE%"
set WHOIS_WATCHING_VERSION_FILE=
call :log "Completed install script"
popd >nul 2>&1
exit /b 0

:header
echo =============================================
echo WHOIS Watching Build and Install Utility
echo ---------------------------------------------
echo This script will:
echo  - Ensure a dedicated Python virtual environment is ready
echo  - Install dependencies from requirements.txt
echo  - Run automated unit tests (pytest)
echo  - Build signed metadata-aware executables with PyInstaller
echo  - Optionally build a Windows setup installer (Inno Setup)
echo  - Optionally package and install the application locally
call :log "Displayed header"
goto :eof

:log
for /f %%t in ('powershell -NoLogo -NoProfile -Command "Get-Date -Format yyyy-MM-ddTHH:mm:ss"') do set TIMESTAMP=%%t
echo [%TIMESTAMP%] %~1>>"%LOG_FILE%"
goto :eof

:error_pushd
echo Failed to change directory to %ROOT_DIR%.
call :log "pushd failure"
exit /b 1

:error_python
echo Python interpreter not found in PATH.
call :log "Python missing"
exit /b 1

:error_venv
echo Failed to create virtual environment.
call :log "venv creation failed"
exit /b 1

:error_activate
echo Failed to activate virtual environment.
call :log "venv activation failed"
exit /b 1

:error_pip
echo Failed to upgrade pip.
call :log "pip upgrade failed"
exit /b 1

:error_requirements
echo Dependency installation failed.
call :log "Dependency installation failed"
exit /b 1

:error_pyinstaller
echo PyInstaller build failed.
call :log "PyInstaller failure"
exit /b 1

:error_manifest
echo Failed to create build manifest.
call :log "Manifest generation failed"
exit /b 1

:error_installer
echo Installer build failed.
call :log "Installer build failed"
exit /b 1

:error_versionfile
echo Failed to generate version metadata file.
call :log "Version file generation failed"
exit /b 1

:error_missing_exe
echo Expected executable not found after build.
call :log "Executable missing"
exit /b 1
