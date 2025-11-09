@echo off
REM ============================================
REM Run Vulnerable Server - Windows
REM ============================================
REM This script runs the vulnerable server in Docker
REM Run this in Terminal 1
REM ============================================

echo.
echo ============================================
echo Starting Vulnerable Server
echo ============================================
echo.
echo Server will be accessible at: http://localhost:80
echo.
echo Press Ctrl+C to stop the server
echo.

REM Stop and remove existing container if running
docker stop vulnerable-server 2>nul
docker rm vulnerable-server 2>nul

REM Run the server
REM For Intel/AMD (x86_64):
docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_x86_64

REM For Apple M1/M2 (ARM), use this instead:
REM docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_amd_arm

echo.
echo Server stopped.
echo.
