// Helpers
function setStatus(message) {
  const el = document.getElementById("webauthn-status");
  if (el) el.textContent = message;
}

// --- CSRF HELPER ---
function getCsrfToken() {
  const tokenEl = document.getElementById("csrf-token-field");
  if (tokenEl) return tokenEl.value;
  
  // Fallback (for protected page where the token is not a field)
  const logoutForm = document.querySelector('.logout-form input[name="csrf_token"]');
  if (logoutForm) return logoutForm.value;

  return null; 
}
// -----------------------

// Helper to log events to the UI and session storage
function logXRay(label, data) {
  // Log to the on-screen console
  const consoleEl = document.getElementById("xray-console");
  if (consoleEl) {
    const timestamp = new Date().toLocaleTimeString();
    const jsonPretty = JSON.stringify(data, (key, value) => {
        if (key === 'source_references') return undefined; 
        return value;
    }, 2);
    
    consoleEl.textContent += `[${timestamp}] ${label}:\n${jsonPretty}\n\n`;
    consoleEl.scrollTop = consoleEl.scrollHeight; 
  }

  // Save to session storage for replay
  try {
    const existing = JSON.parse(sessionStorage.getItem('fido2_flow') || '[]');
    existing.push({ label, data, timestamp: new Date().toISOString() });
    sessionStorage.setItem('fido2_flow', JSON.stringify(existing));
  } catch(e) { console.error("Storage error", e); }
}

// Clear logs when starting a new ceremony
function clearXRayStorage() {
  sessionStorage.removeItem('fido2_flow');
  const consoleEl = document.getElementById("xray-console");
  if (consoleEl) consoleEl.textContent = "";
}

// Convert ArrayBuffer to Base64URL
function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// Convert Base64URL to ArrayBuffer
function base64urlToBuffer(base64url) {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray.buffer;
}

// Load security context from server
async function loadSecurityContext() {
  const loadingEl = document.getElementById("sec-loading");
  const contentEl = document.getElementById("sec-content");

  if (!loadingEl || !contentEl) return;

  try {
    const res = await fetch("/context");
    if (!res.ok) {
      loadingEl.textContent = "Unable to load context (not authenticated?).";
      return;
    }
    const data = await res.json();

    document.getElementById("sec-browser").textContent =
      data.server.browser || data.server.user_agent;
    document.getElementById("sec-platform").textContent =
      data.server.platform || "unknown";
    document.getElementById("sec-origin-server").textContent =
      `${data.server.scheme}://${data.server.host}`;

    const originClient = window.location.origin;
    document.getElementById("sec-origin-client").textContent = originClient;

    const webauthnAvailable = !!window.PublicKeyCredential;
    document.getElementById("sec-webauthn").textContent = webauthnAvailable ? "Yes" : "No";

    let platformAuthnText = "Unknown";
    if (webauthnAvailable && window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      try {
        const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        platformAuthnText = available ? "Likely available" : "Not available";
      } catch (e) {
        platformAuthnText = "Error checking";
      }
    } else if (!webauthnAvailable) {
      platformAuthnText = "No WebAuthn support";
    }
    document.getElementById("sec-platform-authn").textContent = platformAuthnText;

    let interp = "";
    if (!webauthnAvailable) {
      interp = "Your browser does not expose WebAuthn. Passkeys cannot work here.";
    } else if (platformAuthnText.startsWith("Likely")) {
      interp = "This device likely supports platform authenticators (Touch ID, Windows Hello). Ideal for passkeys.";
    } else {
      interp = "WebAuthn is supported, but a platform authenticator may be missing. Hardware keys or synced passkeys may still work.";
    }
    document.getElementById("sec-interpretation").textContent = interp;

    loadingEl.classList.add("hidden");
    contentEl.classList.remove("hidden");
  } catch (err) {
    console.error("Error loading security context:", err);
    loadingEl.textContent = "Failed to load security context.";
  }
}

// Registration process
async function registerPasskey() {
  clearXRayStorage(); // Start fresh
  setStatus("Starting registration...");
  const usernameInput = document.getElementById("username-input");
  const username = usernameInput ? usernameInput.value : "demo-user";

  if (!window.PublicKeyCredential) { 
    setStatus("WebAuthn not supported."); 
    return; 
  }

  try {
    // Step 1: Get challenge from server
    const start = await fetch("/webauthn/register/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username }),
    });
    if (!start.ok) throw new Error("Start failed");
    
    const options = await start.json();
    logXRay("1. SERVER CHALLENGE (Received)", options);

    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if(options.excludeCredentials) options.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id));

    // Step 2: Create credential on device
    const credential = await navigator.credentials.create({ 
        publicKey: options,
        timeout: 60000  // 60 seconds explicit timeout
    });
    
    const credForServer = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
      },
      type: credential.type,
    };
    
    logXRay("2. DEVICE RESPONSE (Sending)", credForServer);

    // Step 3: Send credential to server for verification
    const finish = await fetch("/webauthn/register/finish", {
      method: "POST", 
      headers: { 
        "Content-Type": "application/json",
        "X-CSRF-Token": getCsrfToken() 
      },
      body: JSON.stringify(credForServer),
    });

    if (!finish.ok) {
        const err = await finish.json();
        throw new Error(err.description || "Registration failed");
    }
    
    logXRay("3. SUCCESS", { status: "Verified", stored: true });
    setStatus("Success! Redirecting in 2s...");

    setTimeout(() => window.location.href = "/protected", 2000); 
  } catch (err) {
    console.error(err);
    alert("Registration Failed: " + err.message);
    logXRay("ERROR", { message: err.message });
    setStatus("Failed.");
  }
}

// Login process
async function loginPasskey() {
  clearXRayStorage(); // Start fresh
  setStatus("Starting login...");
  try {
    // Step 1: Get challenge
    const start = await fetch("/webauthn/login/start", { method: "POST" });
    if (!start.ok) throw new Error("Start failed");
    
    const options = await start.json();
    logXRay("1. SERVER CHALLENGE (Received)", options);

    options.challenge = base64urlToBuffer(options.challenge);
    if(options.allowCredentials) options.allowCredentials.forEach(c => c.id = base64urlToBuffer(c.id));

    // Step 2: Get assertion from device
    const assertion = await navigator.credentials.get({ publicKey: options });

    const credForServer = {
      id: assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      response: {
        clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        signature: bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
      },
      type: assertion.type,
    };
    
    logXRay("2. DEVICE SIGNATURE (Sending)", credForServer);

    // Step 3: Verify assertion on server
    const finish = await fetch("/webauthn/login/finish", {
      method: "POST", 
      headers: { 
        "Content-Type": "application/json",
        "X-CSRF-Token": getCsrfToken() 
      },
      body: JSON.stringify(credForServer),
    });

    if (!finish.ok) {
        const err = await finish.json();
        if(finish.status === 400) alert("⚠️ UNKNOWN PASSKEY\n\nServer doesn't recognize this key.");
        throw new Error(err.description);
    }
    
    logXRay("3. SUCCESS", { status: "Verified", session_created: true });
    setStatus("Success! Redirecting in 2s...");
    
    setTimeout(() => window.location.href = "/protected", 2000);
  } catch (err) {
    console.error(err);
    logXRay("ERROR", { message: err.message });
    setStatus("Failed.");
  }
}

//---------------------------------------------------------
// 5. Initialization
//---------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  loadSecurityContext();

  const btnRegister = document.getElementById("btn-register-passkey");
  const btnLogin = document.getElementById("btn-login-passkey");
  
  if (btnRegister) btnRegister.addEventListener("click", registerPasskey);
  if (btnLogin) btnLogin.addEventListener("click", loginPasskey);
});

// --- SECURITY: SESSION CLEANUP ---
document.addEventListener("DOMContentLoaded", () => {
    
    // 1. CLEAN EXIT: Wipe evidence when clicking "Logout"
    // We look for any link or button that mentions "logout"
    const logoutBtn = document.querySelector('a[href*="logout"], .logout-icon, .btn-revoke');
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            console.log("🔒 Securing session: Forensic evidence wiped.");
            sessionStorage.removeItem('fido2_flow');
        });
    }

    // 2. CLEAN START: Wipe evidence if we land on the Login Page
    // This catches cases where the session expired or user closed the tab
    const isLoginPage = document.querySelector('.tab-container'); // Only login page has tabs
    if (isLoginPage) {
        sessionStorage.removeItem('fido2_flow');
    }
});