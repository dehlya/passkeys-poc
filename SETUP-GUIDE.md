# Quick Setup Guide

Get the Passkeys POC running in under 5 minutes!

## Prerequisites Check

Before starting, verify you have:

```bash
# Check Python version (need 3.9+)
python --version

# Check Node.js version (need 18+, optional for tests)
node --version

# Check pip
pip --version
```

## Step-by-Step Setup

### 1. Clone & Navigate

```bash
git clone https://github.com/dehlya/passkeys-poc.git
cd passkeys-poc
```

### 2. Create Virtual Environment

**On macOS/Linux:**

```bash
cd src
python3 -m venv venv
source venv/bin/activate
```

**On Windows:**

```cmd
cd src
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Expected packages:
- Flask
- python-dotenv
- webauthn
- requests
- passkeys
- user-agents

### 4. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Generate a secure secret key
python -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')" >> .env
```

Your `.env` file should now contain:

```env
SECRET_KEY=your-generated-secret-key-here
PRODUCTION=false
```

**Note:** Corbado configuration is optional. Skip it for now - you can still use the Protocol Auditing mode!

### 5. Run the Application

```bash
python app.py
```

You should see:

```
⚠️  IMPORTANT: Access this app at http://localhost:5000
   (WebAuthn requires a secure context: localhost or https)

* Running on http://127.0.0.1:5000
* Debug mode: on
```

### 6. Open in Browser

Navigate to: **http://localhost:5000**

## First-Time Usage

### Try Protocol Auditing Mode (No Vendor Setup Needed!)

1. Click **"Login Demo"** in the navigation
2. Select the **"Protocol Auditing (Build)"** tab
3. Enter any username (e.g., `test-user`)
4. Click **"Register Identity"**
5. Follow your browser's passkey prompt (TouchID, Windows Hello, etc.)
6. Watch the protocol trace appear in real-time!

### Expected Flow

1. **Registration**:
   - Server generates a challenge
   - Your device creates a key pair
   - Public key stored on server
   - Protocol details shown in terminal

2. **Authentication**:
   - Click "Authenticate"
   - Device signs challenge with private key
   - Server verifies signature
   - Access granted to dashboard

3. **Forensics**:
   - View session telemetry
   - See stored credentials
   - Examine protocol timeline

## Troubleshooting

### "WebAuthn not supported"

- Use a modern browser: Chrome 67+, Firefox 60+, Safari 14+, Edge 18+
- Ensure you're on `localhost` or HTTPS (WebAuthn requirement)

### "ModuleNotFoundError"

```bash
# Make sure virtual environment is activated
source venv/bin/activate  
# or venv\Scripts\activate on Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Database errors

```bash
# Delete and recreate database
rm poc_data.db
python app.py  
# Will auto-create on startup
```

### Port already in use

```python
# Change port in app.py (last line):
app.run(debug=True, host="0.0.0.0", port=5001)
# or any free port
```

### Corbado mode not working

- This is optional! Protocol Auditing mode works without it
- To use: Sign up at corbado.com and add credentials to `.env`

## Testing Different Authenticators

### Platform Authenticators (Built-in)

- **macOS**: TouchID
- **Windows**: Windows Hello (PIN, Face, Fingerprint)
- **iOS/iPadOS**: FaceID / TouchID
- **Android**: Fingerprint / Face Unlock

### External Authenticators

- YubiKey
- Titan Security Key
- Any FIDO2-compliant device

### Synced Passkeys

- iCloud Keychain (Apple)
- Google Password Manager
- 1Password

## Optional: E2E Testing

If you want to run automated tests:

```bash
# Install Node dependencies
npm install

# Run Playwright tests
npm run test:e2e
```

## Learning Path

Recommended exploration order:

1. **Start**: Register in Protocol Auditing mode
2. **Observe**: Watch the live protocol trace
3. **Analyze**: Go to Dashboard → view session details
4. **Deep Dive**: Check Workflow page for timeline
5. **Compare**: Try Corbado mode (if configured) to see the difference
6. **Experiment**: Try different authenticators, browsers

## Security Notes

- Safe to use on `localhost`
- No real credentials stored (test data only)
- Don't expose port 5000 to the internet
- Development mode only (debug=True)

## Next Steps

After setup:

- Read the full [README.md](README.md)
- Check [SECURITY.md](SECURITY.md) for limitations
- Review the code to understand WebAuthn flow
- Try the workflow analysis features

## Still Having Issues?

1. Check existing [GitHub Issues](https://github.com/dehlya/passkeys-poc/issues)
2. Open a new issue with:
   - OS and version
   - Python version
   - Browser and version
   - Error message/screenshot
   - Steps you followed

---

**Happy learning!**

*Remember: This is for education. Explore, break things, learn from it!*
