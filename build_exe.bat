@echo off
rem Builds two Windows programs into dist\ :  EntraPostureScanner-GUI.exe (window) and EntraPostureScanner-CLI.exe (command line).
rem Needs 64-bit Python 3.10-3.13 from python.org with "Add python.exe to PATH" ticked. Run from this folder.
setlocal
cd /d "%~dp0"
set PY=python
where py >nul 2>nul && set PY=py -3
%PY% --version || (echo Python was not found. Install it from https://www.python.org/downloads/ & exit /b 1)
%PY% -m venv .buildenv || exit /b 1
call .buildenv\Scripts\activate.bat
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements.txt pyinstaller || exit /b 1
pyinstaller --noconfirm --clean --onefile --noconsole --name EntraPostureScanner-GUI --collect-submodules entra_scan --collect-data certifi entra_posture_gui.py || exit /b 1
pyinstaller --noconfirm --onefile --name EntraPostureScanner-CLI --collect-submodules entra_scan --collect-data certifi entra_posture_scan.py || exit /b 1
echo.
echo Done:  dist\EntraPostureScanner-GUI.exe  and  dist\EntraPostureScanner-CLI.exe
echo Test:  dist\EntraPostureScanner-CLI.exe --version
