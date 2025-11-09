#!/bin/bash
# ============================================
# Run Vulnerable Server - Mac/Linux
# ============================================
# This script runs the vulnerable server in Docker
# Run this in Terminal 1
# ============================================

echo ""
echo "============================================"
echo "Starting Vulnerable Server"
echo "============================================"
echo ""
echo "Server will be accessible at: http://localhost:80"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Stop and remove existing container if running
docker stop vulnerable-server 2>/dev/null
docker rm vulnerable-server 2>/dev/null

# Detect architecture
ARCH=$(uname -m)

if [[ "$ARCH" == "arm64" ]] || [[ "$ARCH" == "aarch64" ]]; then
    # Apple M1/M2 or ARM
    echo "Detected ARM architecture - using ARM image"
    docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_amd_arm
else
    # Intel/AMD x86_64
    echo "Detected x86_64 architecture - using x86_64 image"
    docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_x86_64
fi

echo ""
echo "Server stopped."
echo ""
