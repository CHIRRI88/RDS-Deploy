@echo off
echo.
echo ========================================
echo  BusinessVision Remote Desktop Setup
echo ========================================
echo.
echo This will configure your computer for BusinessVision remote access.
echo.
pause

powershell -ExecutionPolicy Bypass -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex (irm 'https://raw.githubusercontent.com/CHIRRI88/RDS-Deploy/main/Install-BV-Remote-Encrypted.ps1') }"

echo.
echo ========================================
echo  Setup process finished.
echo ========================================
echo.
pause
