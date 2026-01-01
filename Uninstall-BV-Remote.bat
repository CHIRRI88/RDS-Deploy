@echo off
echo.
echo ========================================
echo  BusinessVision Remote Desktop Uninstall
echo ========================================
echo.
echo This will remove the BusinessVision remote access configuration.
echo.
echo The following will be removed:
echo   - Root CA certificate
echo   - Desktop shortcuts
echo   - RDP files and icons
echo   - Stored credentials
echo.
pause

powershell -ExecutionPolicy Bypass -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex (irm 'https://raw.githubusercontent.com/CHIRRI88/RDS-Deploy/main/Uninstall-BV-Remote-Encrypted.ps1') }"

echo.
echo ========================================
echo  Uninstall process finished.
echo ========================================
echo.
pause
