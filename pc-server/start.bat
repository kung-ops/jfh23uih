@echo off
title Old iPhone Web Gateway (port 8106)
cd /d "%~dp0"

REM --- ask for Administrator (needed to fix the firewall for hotspots) ---
net session >nul 2>nul
if %errorlevel% neq 0 (
  echo Asking for Administrator so the firewall can be fixed for hotspots...
  powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)

cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js is not installed. Get it from https://nodejs.org and run this again. & pause & exit /b)

REM --- FIREWALL: Windows calls a phone hotspot a "Public" network and blocks the gateway there.
REM     Allow Node on ALL network types (Private + Public + Domain), TCP and UDP (UDP = oldweb.local name).
for /f "delims=" %%N in ('where node') do if not defined NODEEXE set "NODEEXE=%%N"
REM     When you once clicked "Allow" only for Private, Windows ALSO made a hidden BLOCK rule for
REM     Public networks - and Block always wins. Remove only those Block rules for node.exe.
powershell -NoProfile -Command "Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*\node.exe' } | Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' } | Remove-NetFirewallRule" >nul 2>nul
netsh advfirewall firewall delete rule name="OldWeb gateway" >nul 2>nul
netsh advfirewall firewall add rule name="OldWeb gateway" dir=in action=allow program="%NODEEXE%" protocol=TCP localport=8106 profile=any enable=yes >nul
netsh advfirewall firewall add rule name="OldWeb gateway" dir=in action=allow program="%NODEEXE%" protocol=UDP localport=5353 profile=any enable=yes >nul
echo Firewall: OldWeb allowed on home Wi-Fi AND hotspots.

if not exist node_modules (
  echo Installing, please wait...
  call npm install --omit=dev --no-audit --no-fund
)
node server.js
pause
