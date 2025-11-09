# Timing Side-Channel Attack

Interactive tool demonstrating timing attacks against vulnerable password verification.

---

## Quick Start

### Terminal 1: Start Server (Docker)

**Windows:**
```bash
docker-run-server.bat
```

**Mac/Linux:**
```bash
./docker-run-server.sh
```

Server runs on `http://localhost:80`

### Terminal 2: Run Attack (Python)

```bash
python src/main.py
```

That's it! Simple Python script with interactive menu.

---

## Interactive Menu

```
============================================================
TIMING ATTACK - INTERACTIVE MENU
============================================================
1. Start New Attack
2. View Attack History
3. Test Password
4. Exit
============================================================
```

### Option 1: Start New Attack
- Cracks password using timing side-channel
- Shows progress for each character discovered
- Saves result to `attack_results.json`
- Offers to test password when complete

### Option 2: View Attack History
- Shows all previous attacks
- Username, password, time taken, difficulty

### Option 3: Test Password
- Manually test any username/password
- Verifies if correct
- Shows response time

### Option 4: Exit
- Closes the program

---

## Configuration

Edit `.env`:

```bash
TARGET_USERNAME=316279942        # Your username
USE_LOCAL_SERVER=true            # true=localhost, false=remote
LOG_LEVEL=INFO                   # DEBUG, INFO, WARNING, ERROR
ATTACK_DIFFICULTY=1              # 1-5 (1=easiest)
MAX_PASSWORD_LENGTH=32           # Maximum length to try
```

---

## How It Works

### The Vulnerability

Naive character-by-character comparison:

```python
for i in range(len(password)):
    if guess[i] != password[i]:
        return False  # Early return = timing leak!
```

Correct characters take longer (more comparisons).

### The Attack

1. Try all 26 letters at position 0
2. Measure response time (20+ samples each)
3. Select character with longest time
4. Repeat for next position
5. Stop when password verified

### Speed

- **Brute force:** 26^10 = 141 trillion attempts
- **Timing attack:** 26×10 = 260 attempts
- **Speed up:** ~54 trillion times faster!

---

## Expected Results

### Timing
- **Difficulty 1:** 3-5 minutes
- **Difficulty 2-5:** 5-15 minutes

### Success
✓ Password displayed
✓ Saved to history
✓ "ATTACK COMPLETE" message

### Failure
✗ Connection errors
✗ Gets stuck at same position
✗ Wrong characters

---

## Requirements

### Python
- Python 3.11+
- Dependencies: `pip install -r requirements.txt`

### Docker
- Docker Desktop (for server)
- Windows/Mac/Linux compatible

---

## Project Structure

```
├── src/
│   ├── main.py              # Run this! Interactive menu
│   ├── core/                # Interfaces & models
│   ├── services/            # HTTP, timing, analysis
│   ├── attack/              # Attack logic
│   └── utils/               # Logger, stats
├── config/config.yaml       # Advanced settings
├── docker-run-server.bat    # Start server (Windows)
├── docker-run-server.sh     # Start server (Mac/Linux)
├── .env                     # Configuration
├── requirements.txt         # Python dependencies
└── attack_results.json      # History (generated)
```

---

## Troubleshooting

### "Server container not detected"
Start server first in Terminal 1:
```bash
docker-run-server.bat
```

### "Port 80 already in use"
```bash
# Windows: Stop IIS
iisreset /stop

# Mac/Linux: Stop Apache
sudo apachectl stop
```

### "Python not found"
```bash
# Install Python 3.11+
python --version

# Install dependencies
pip install -r requirements.txt
```

### "Cannot connect to server"
Test manually:
```bash
curl "http://localhost/?user=test&password=test&difficulty=1"
# Should return: {"result": false}
```

### "Attack gets stuck"
- Set `LOG_LEVEL=DEBUG` in `.env`
- Check server is still running
- Verify network connectivity

---

## Apple M1/M2 Users

Edit `docker-run-server.bat` (or `.sh`) line 23:

```bash
# Change from:
docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_x86_64

# To:
docker run --name vulnerable-server -p 80:8080 amarmic/attacks_on_implementations:Assignment1_amd_arm
```

---

## Files Generated

- **attack_results.json** - History of all attacks
- **attack.log** - Detailed logs

---

## FAQ

**Q: Why max length 32?**
A: Default from assignment. Change via `MAX_PASSWORD_LENGTH` in `.env`

**Q: Can I change difficulty?**
A: Yes - edit `ATTACK_DIFFICULTY` in `.env` (1-5)

**Q: Where are passwords saved?**
A: In `attack_results.json` (JSON format)

**Q: How do I view logs?**
A: Check `attack.log` or set `LOG_LEVEL=DEBUG`

---

## Security Notice

⚠️ **Educational purposes only**

Never use against systems without explicit permission. Unauthorized access is illegal.

### Mitigation

Use constant-time comparison:
```python
import hmac
def secure_compare(a, b):
    return hmac.compare_digest(a, b)
```

---

## Summary

**Two terminals, two commands:**

1. Terminal 1: `docker-run-server.bat` (Start server)
2. Terminal 2: `python src/main.py` (Run attack)

Simple!