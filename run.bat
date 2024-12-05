@echo off
echo Checking Python libraries...

set missing_lib=0

python -m pip show aiohttp >nul 2>&1
if %errorlevel% neq 0 (
    echo Missing library aiohttp. Installing...
    python -m pip install aiohttp
    set /a missing_lib+=1
)

python -m pip show cryptography >nul 2>&1
if %errorlevel% neq 0 (
    echo Missing library cryptography. Installing...
    python -m pip install cryptography
    set /a missing_lib+=1
)

python -m pip show colorama >nul 2>&1
if %errorlevel% neq 0 (
    echo Missing library colorama. Installing...
    python -m pip install colorama
    set /a missing_lib+=1
)

python -m pip show requests >nul 2>&1
if %errorlevel% neq 0 (
    echo Missing library requests. Installing...
    python -m pip install requests
    set /a missing_lib+=1
)

if %missing_lib% equ 0 (
    echo All required libraries are already installed.
) else (
    echo Finished installing missing libraries.
)

if not exist keyboxs (
    mkdir keyboxs
    echo Created new folder...
)

echo Running check...
python main.py -b keyboxs\

pause
