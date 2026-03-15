@echo off
setlocal enabledelayedexpansion
title Xbox Collection Tracker - Launcher
chcp 65001 >nul 2>&1

:: Read version from version.txt
set "VER=?"
if exist "%~dp0version.txt" (
    set /p VER=<"%~dp0version.txt"
)

echo.
echo   ██╗  ██╗ ██████╗████████╗
echo   ╚██╗██╔╝██╔════╝╚══██╔══╝
echo    ╚███╔╝ ██║        ██║
echo    ██╔██╗ ██║        ██║
echo   ██╔╝ ██╗╚██████╗   ██║
echo   ╚═╝  ╚═╝ ╚═════╝   ╚═╝
echo.
echo   Xbox Collection Tracker v!VER! by Freshdex
echo.

:: -------------------------------------------------------------------
:: 1. Find Python
:: -------------------------------------------------------------------
set "PYTHON="

:: Try 'python' first
python --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON=python"
    goto :found_python
)

:: Try 'py' launcher
py --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON=py"
    goto :found_python
)

:: Try 'python3'
python3 --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON=python3"
    goto :found_python
)

:: Python not found - offer to install
echo   [!] Python is not installed or not in PATH.
echo.
echo       [1] Install Python via winget (recommended)
echo       [2] Open python.org download page
echo       [3] Exit
echo.
set /p "PYCHOICE=  Pick [1/2/3]: "

if "!PYCHOICE!"=="1" (
    echo.
    echo   [*] Installing Python via winget...
    winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    if !errorlevel! neq 0 (
        echo.
        echo   [!] winget install failed. Try option 2 or install Python manually.
        pause
        exit /b 1
    )
    echo.
    echo   [+] Python installed. Please close and reopen this launcher
    echo       so the PATH update takes effect.
    pause
    exit /b 0
)
if "!PYCHOICE!"=="2" (
    echo.
    echo   [*] Opening python.org...
    start https://www.python.org/downloads/
    echo.
    echo   Install Python, tick "Add Python to PATH", then rerun this launcher.
    pause
    exit /b 0
)
exit /b 0

:found_python
:: Show version
for /f "tokens=*" %%v in ('!PYTHON! --version 2^>^&1') do set "PYVER=%%v"
echo   [+] !PYVER!
echo.

:: -------------------------------------------------------------------
:: 2. Check and install packages
:: -------------------------------------------------------------------
echo   [*] Checking dependencies...

!PYTHON! -c "import ecdsa" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [!] Missing packages detected. Installing from requirements.txt...
    echo.
    !PYTHON! -m pip install -r "%~dp0requirements.txt"
    if !errorlevel! neq 0 (
        echo.
        echo   [!] pip install failed. Try manually: pip install -r requirements.txt
        pause
        exit /b 1
    )
    echo.
    echo   [+] Dependencies installed.
) else (
    echo   [+] All dependencies OK.
)
echo.

:: -------------------------------------------------------------------
:: 3. Menu
:: -------------------------------------------------------------------
:menu
echo       [1] Launch XCT Tools
echo       [2] Launch XCT Desktop
echo       [3] Launch XCT Local Portal
echo       [4] Launch xct.live
echo       [0] Exit
echo.
set /p "CHOICE=  Pick: "

if "!CHOICE!"=="1" goto :launch_xct
if "!CHOICE!"=="2" goto :launch_desktop
if "!CHOICE!"=="3" goto :open_local
if "!CHOICE!"=="4" goto :open_live
if "!CHOICE!"=="0" exit /b 0
echo   [!] Invalid choice.
echo.
goto :menu

:: -------------------------------------------------------------------
:: Launch XCT Desktop (Tauri GUI)
:: -------------------------------------------------------------------
:launch_desktop
echo.
set "DESKTOP_DIR=%~dp0xct-desktop"
set "RELEASE_EXE=!DESKTOP_DIR!\src-tauri\target\release\xct-desktop.exe"
set "DEBUG_EXE=!DESKTOP_DIR!\src-tauri\target\debug\xct-desktop.exe"

:: Check xct-desktop directory exists
if not exist "!DESKTOP_DIR!" (
    echo   [!] ERROR: xct-desktop directory not found at:
    echo       !DESKTOP_DIR!
    echo.
    goto :menu
)

:: 1. Try release build
if not exist "!RELEASE_EXE!" goto :no_release
echo   [*] Found release build.
echo   [*] Launching XCT Desktop...
start "" "!RELEASE_EXE!"
echo   [+] Launched.
echo.
goto :menu
:no_release

:: 2. No release build — compile and run via tauri dev
echo   [*] No pre-built executable found. Need to compile from source.
echo.

:: Check Node.js/npm
where npm >nul 2>&1
if !errorlevel! neq 0 (
    echo   [!] ERROR: npm not found.
    echo       Install Node.js from https://nodejs.org/ to build XCT Desktop.
    echo.
    goto :menu
)
for /f "tokens=*" %%v in ('call npm --version 2^>^&1') do echo   [+] npm %%v

:: Check node_modules exist
if not exist "!DESKTOP_DIR!\node_modules" (
    echo   [*] Installing npm dependencies...
    pushd "!DESKTOP_DIR!"
    npm install
    popd
    if !errorlevel! neq 0 (
        echo   [!] ERROR: npm install failed.
        echo.
        goto :menu
    )
)

:: Check Rust/cargo (also check default rustup install path since PATH may not be refreshed)
set "CARGO_BIN=%USERPROFILE%\.cargo\bin"
if exist "!CARGO_BIN!\cargo.exe" (
    set "PATH=!CARGO_BIN!;!PATH!"
)
where cargo >nul 2>&1
if !errorlevel! neq 0 (
    echo.
    echo   [!] ERROR: Rust ^(cargo^) not found.
    echo       Tauri requires Rust to compile the desktop app.
    echo.
    echo       Install Rust:
    echo         [1] Install via winget   ^(winget install Rustlang.Rustup^)
    echo         [2] Open rustup.rs       ^(manual install^)
    echo         [3] Back to menu
    echo.
    set /p "RUSTCHOICE=  Pick [1/2/3]: "
    if "!RUSTCHOICE!"=="1" (
        echo.
        echo   [*] Installing Rust via winget...
        winget install Rustlang.Rustup --accept-package-agreements --accept-source-agreements
        if !errorlevel! neq 0 (
            echo   [!] winget install failed. Try option 2.
            echo.
            goto :menu
        )
        echo.
        echo   [+] Rust installed. Please close and reopen this launcher
        echo       so the PATH update takes effect.
        pause
        exit /b 0
    )
    if "!RUSTCHOICE!"=="2" (
        start "" "https://rustup.rs"
        echo.
        echo   Install Rust, then reopen this launcher.
        pause
        exit /b 0
    )
    goto :menu
)
for /f "tokens=*" %%v in ('call cargo --version 2^>^&1') do echo   [+] %%v

:: Check Tauri CLI
echo   [*] Checking Tauri CLI...
pushd "!DESKTOP_DIR!"
call npx tauri --version >nul 2>&1
if !errorlevel! neq 0 (
    echo   [!] ERROR: Tauri CLI not found or failed.
    echo       Try running: cd xct-desktop ^&^& npm install
    popd
    echo.
    goto :menu
)
for /f "tokens=*" %%v in ('call npx tauri --version 2^>^&1') do echo   [+] tauri-cli %%v
popd

:: All checks passed — build release (embeds frontend, no dev server needed)
echo.
echo   [*] Building XCT Desktop release...
echo   [*] First build will take several minutes to compile all dependencies.
echo   [*] Subsequent builds are much faster.
echo.
pushd "!DESKTOP_DIR!"
call npx tauri build 2>&1
set "TAURI_EXIT=!errorlevel!"
popd
echo.
if !TAURI_EXIT! equ 0 (
    echo   [+] Build successful!
    if exist "!RELEASE_EXE!" (
        echo   [*] Launching XCT Desktop...
        start "" "!RELEASE_EXE!"
        echo   [+] Launched.
    )
)
if !TAURI_EXIT! neq 0 (
    echo   [!] Build failed with error code !TAURI_EXIT!
    echo   [*] Check the output above for details.
    echo.
)
goto :menu

:: -------------------------------------------------------------------
:: Launch XCT.py
:: -------------------------------------------------------------------
:launch_xct
echo.
!PYTHON! "%~dp0XCT.py"
echo.
goto :menu

:: -------------------------------------------------------------------
:: Open local HTML portal
:: -------------------------------------------------------------------
:open_local
echo.

:: Prefer combined index
if exist "%~dp0accounts\XCT.html" (
    echo   [*] Opening accounts\XCT.html ...
    start "" "%~dp0accounts\XCT.html"
    echo.
    goto :menu
)

:: Fall back to first per-account HTML found
for /d %%d in ("%~dp0accounts\*") do (
    if exist "%%d\XCT.html" (
        echo   [*] Opening %%d\XCT.html ...
        start "" "%%d\XCT.html"
        echo.
        goto :menu
    )
)

echo   [!] No HTML page found. Run XCT Tools first to generate your collection page.
echo.
goto :menu

:: -------------------------------------------------------------------
:: Open live portal
:: -------------------------------------------------------------------
:open_live
echo.
echo   [*] Opening xct.live ...
start "" "https://xct.live"
echo.
goto :menu
