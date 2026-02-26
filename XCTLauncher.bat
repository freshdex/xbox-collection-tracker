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
echo       [2] Launch XCT Local Portal
echo       [3] Launch XCT Live Portal
echo       [0] Exit
echo.
set /p "CHOICE=  Pick: "

if "!CHOICE!"=="1" goto :launch_xct
if "!CHOICE!"=="2" goto :open_local
if "!CHOICE!"=="3" goto :open_live
if "!CHOICE!"=="0" exit /b 0
echo   [!] Invalid choice.
echo.
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
echo   [*] Opening xct.freshdex.app ...
start "" "https://xct.freshdex.app"
echo.
goto :menu
