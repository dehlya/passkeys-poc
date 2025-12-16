import sqlite3
import secrets
import os
import base64
from datetime import datetime
from user_agents import parse
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    flash,
    jsonify,
    g
)

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import (
    parse_registration_credential_json,
    parse_authentication_credential_json
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    AuthenticationCredential,
    ResidentKeyRequirement  
)
from corbado_python_sdk import Config as CorbadoConfig, CorbadoSDK
import config

RP_NAME = "Passkeys PoC Lab"
RP_ID = "localhost"
ORIGIN = "http://localhost:5000"


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    
    app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

    def get_db():
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect('poc_data.db')
            db.row_factory = sqlite3.Row
        return db

    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, '_database', None)
        if db is not None: db.close()

    def init_db():
        with app.app_context():
            db = get_db()
            db.execute('''CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))''')
            db.commit()
    init_db()

    corbado_config = CorbadoConfig(
        project_id=config.CORBADO_PROJECT_ID,
        api_secret=config.CORBADO_API_SECRET,
        frontend_api=f"https://{config.CORBADO_PROJECT_ID}.frontendapi.cloud.corbado.io",
        backend_api="https://backendapi.cloud.corbado.io"
    )
    corbado_sdk = CorbadoSDK(config=corbado_config)

    def to_base64url(data):
        if isinstance(data, str): data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

    @app.before_request
    def generate_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_security_context():
        return dict(csp_nonce=g.csp_nonce)

    @app.context_processor
    def inject_csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return {"csrf_token": token}
    
    # --- CSRF VALIDATION HELPER ---
    def check_csrf():
        """
        Validates the CSRF token sent in the X-CSRF-Token header for AJAX POST/DELETE calls.
        FIDO2 is resistant to CSRF via the origin check, but this is a security best practice
        for all modifying API endpoints.
        """
        token_header = request.headers.get("X-CSRF-Token")
        token_session = session.get("csrf_token")
        
        # Enforce token check for all modifying API methods
        if request.method in ["POST", "DELETE", "PUT", "PATCH"]:
            # Check for JSON/AJAX header
            if not token_header or token_header != token_session:
                # If neither token matches, abort with 403
                abort(403, description="CSRF token missing or incorrect.")


    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        nonce = getattr(g, "csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' https://unpkg.com https://*.corbado.io https://*.corbado.com 'nonce-{nonce}'; "
            "style-src 'self' https://unpkg.com https://fonts.googleapis.com 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' https://*.corbado.io https://*.corbado.com;"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Disable caching to prevent session issues
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
        return response

    # Routes

    @app.route("/")
    def index(): return render_template("index.html", user=session.get("user_id"))

    @app.route("/login", methods=["GET"])
    def login():
        # FIX: If already logged in, redirect to dashboard immediately
        if session.get("user_id"):
            return redirect(url_for("protected"))
            
        return render_template("login.html", project_id=config.CORBADO_PROJECT_ID, user=session.get("user_id"))

    @app.route("/webauthn/register/start", methods=["POST"])
    def webauthn_register_start():
        body = request.get_json(silent=True) or {}
        username = body.get("username", "demo-user")
        user_id = username 
        session["reg_user_id"] = user_id
        session["reg_username"] = username

        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id.encode(),
            user_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
                
                # Use cross-platform authenticators (like phones or security keys)
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                
                # Require resident key for usernameless login
                resident_key=ResidentKeyRequirement.REQUIRED
            ),
        )
        session["challenge"] = to_base64url(options.challenge)
        return options_to_json(options)

    @app.route("/webauthn/register/finish", methods=["POST"])
    def webauthn_register_finish():
        check_csrf()
        
        # POP FIRST to prevent reuse
        challenge_b64 = session.pop("challenge", None)
        if not challenge_b64:
            abort(400, "Registration ceremony expired or already used")
        
        try:
            credential = parse_registration_credential_json(request.get_json())
            expected_challenge = base64url_to_bytes(challenge_b64)
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
            )
        except ValueError as e:
            # Expected protocol violations - safe to show
            abort(400, description=f"Registration failed: {str(e)}")
        except Exception as e:
            # Unexpected errors - log but don't expose
            app.logger.error(f"WebAuthn verification error: {str(e)}", exc_info=True)
            abort(400, description="Registration failed due to an internal error")

        safe_cred_id = to_base64url(verification.credential_id)
        db = get_db()
        db.execute("INSERT OR IGNORE INTO users (id, username, display_name) VALUES (?, ?, ?)",
                (session["reg_user_id"], session["reg_username"], "Demo User"))
        db.execute("INSERT INTO credentials (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)",
                (safe_cred_id, session["reg_user_id"], verification.credential_public_key, verification.sign_count))
        db.commit()

        session["user_id"] = session["reg_user_id"]
        session["security_summary"] = {
            "event": "Registration (Manual)",
            "rp_id": RP_ID,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "challenge_used": secrets.token_hex(8) + "..."
        }
        # Challenge already popped - no need to pop again
        return jsonify({"status": "ok"})

    @app.route("/webauthn/login/start", methods=["POST"])
    def webauthn_login_start():
        options = generate_authentication_options(rp_id=RP_ID, user_verification=UserVerificationRequirement.PREFERRED)
        session["challenge"] = to_base64url(options.challenge)
        return options_to_json(options)

    @app.route("/webauthn/login/finish", methods=["POST"])
    def webauthn_login_finish():
        check_csrf() 
       # POP FIRST to prevent reuse
        challenge_b64 = session.pop("challenge", None)
        if not challenge_b64:
            abort(400, "Login ceremony expired or already used")
            
        try:
            credential = parse_authentication_credential_json(request.get_json())
            target_cred_id = credential.id 
            db = get_db()
            cred_row = db.execute("SELECT * FROM credentials WHERE id = ?", (target_cred_id,)).fetchone()
            if not cred_row: abort(400, description="Unknown credential ID.")

            expected_challenge = base64url_to_bytes(challenge_b64)
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                credential_public_key=cred_row["public_key"],
                credential_current_sign_count=cred_row["sign_count"],
            )
        except ValueError as e:
            # Expected protocol violations - safe to show
            # Log for debugging
            app.logger.warning(f"Authentication failed for credential {credential.id[:8]}: {str(e)}")
            # Generic message to user
            abort(400, description="Authentication failed. Please try again.")
        except Exception as e:
            # Unexpected errors - log but don't expose
            app.logger.error(f"WebAuthn verification error: {str(e)}", exc_info=True)
            abort(400, description="Authentication failed due to an internal error")

        db.execute("UPDATE credentials SET sign_count = ? WHERE id = ?", (verification.new_sign_count, target_cred_id))
        db.commit()
        
        session["user_id"] = cred_row["user_id"]
        session["security_summary"] = {
            "event": "Login (Manual)",
            "rp_id": RP_ID,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "challenge_used": secrets.token_hex(8) + "..."
        }
        
        return jsonify({"status": "ok"})

    # Account Management APIs
    @app.route("/api/credentials", methods=["GET"])
    def list_credentials():
        if not session.get("user_id"): return abort(401)
        db = get_db()
        rows = db.execute("SELECT id, sign_count FROM credentials WHERE user_id = ?", (session.get("user_id"),)).fetchall()
        return jsonify([{"id": row["id"], "sign_count": row["sign_count"]} for row in rows])

    @app.route("/api/credentials/<cred_id>", methods=["DELETE"])
    def delete_credential(cred_id):
        check_csrf()
        if not session.get("user_id"): return abort(401)
        # Simplified CSRF for the deletion API to avoid complexity in this snippet
        db = get_db()
        db.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", (cred_id, session.get("user_id")))
        db.commit()
        return jsonify({"status": "deleted"})

    @app.route("/corbado/callback")
    def corbado_callback():
        token = request.cookies.get("cbo_session_token")
        if not token: return redirect(url_for("login"))
        try:
            validation_result = corbado_sdk.sessions.validate_token(token)
            session["user_id"] = validation_result.user_id
            session["security_summary"] = {
                "event": "Login (Corbado)",
                "rp_id": config.CORBADO_PROJECT_ID,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "challenge_used": "Managed by SDK",
                "origin": "Verified by SDK"
            }
            return redirect(url_for("protected"))
        except Exception:
            return redirect(url_for("login"))

    @app.route("/protected")
    def protected():
        if not session.get("user_id"): return redirect(url_for("login"))
        return render_template("protected.html", user=session.get("user_id"), security_summary=session.get("security_summary"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/context")
    def context():
        """
        Returns the security context with robust fallbacks.
        """
        ua_string = request.headers.get('User-Agent', '')
        ua = parse(ua_string)

        # Robust parsing: If library returns 'Other', try to extract from raw string
        browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
        if "Other" in browser or browser == "":
            browser = "Browser Detected" # Generic fallback

        os_name = f"{ua.os.family} {ua.os.version_string}".strip()
        if "Other" in os_name or os_name == "":
            # Manual fallback for common OSs if library fails
            if "Windows" in ua_string: os_name = "Windows"
            elif "Mac" in ua_string: os_name = "macOS"
            elif "Linux" in ua_string: os_name = "Linux"
            else: os_name = "Unknown OS"

        return jsonify({
            "server": {
                "browser": browser,
                "platform": os_name,
                "device": ua.device.family if ua.device.family != "Other" else "Desktop",
                "ip": "localhost", # Localhost for PoC
                "scheme": request.scheme,
                "host": request.host
            }
        })
        
    @app.route("/learn")
    def learn():
        user = session.get("user_id")
        ctx = {}
        
        if user:
            # FIX: Use the robust 'user_agents' library instead of Flask's default
            ua_string = request.headers.get('User-Agent', '')
            ua = parse(ua_string)
            
            # 1. Robust Platform Detection with Fallbacks
            os_name = f"{ua.os.family} {ua.os.version_string}".strip()
            if "Other" in os_name or os_name == "":
                # Fallback checks if library fails
                if "Windows" in ua_string: os_name = "Windows"
                elif "Mac" in ua_string: os_name = "macOS"
                elif "Linux" in ua_string: os_name = "Linux"
                else: os_name = "Unknown OS"

            # Add Hardware Security Context (TPM/Enclave)
            platform_detail = os_name
            if "Windows" in os_name:
                platform_detail += " (TPM 2.0 Likely)"
            elif "Mac" in os_name or "iOS" in os_name:
                platform_detail += " (Secure Enclave)"
            elif "Linux" in os_name:
                platform_detail += " (USB Security Key / Soft Token)"

            # 2. Robust Browser Detection
            browser_raw = f"{ua.browser.family} {ua.browser.version_string}".strip()
            if "Other" in browser_raw or browser_raw == "":
                browser_raw = "Unknown Client"

            # 3. Gather security context data
            summary = session.get("security_summary", {})
            auth_event = summary.get("event", "Unknown")
            
            # 4. Transport Analysis logic
            transport_guess = "Internal (Platform Auth)"
            if "CDA" in auth_event: 
                transport_guess = "Hybrid (Cross-Device)"
            elif "Corbado" in auth_event: 
                transport_guess = "Managed Cloud"

            ctx = {
                "user": user,
                "ip": request.remote_addr,
                "browser_raw": browser_raw,
                "platform": platform_detail,
                "timestamp": datetime.now().strftime("%H:%M:%S UTC"),
                "auth_method": "FIDO2 / WebAuthn (CTAP2)",
                "transport_guess": transport_guess,
                # Ensure ORIGIN is defined globally or use request.host_url
                "origin": request.host_url, 
                "session_id": secrets.token_hex(4).upper() 
            }
            
        return render_template("learn.html", user=user, ctx=ctx)

    @app.route("/workflow")
    def workflow(): return render_template("workflow.html", user=session.get("user_id"))
    

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def handle_errors(error):
        if request.path.startswith("/webauthn/") or request.path.startswith("/context"):
            return jsonify({"error": "Error", "description": str(error)}), 500
        return (render_template("error.html", error=error), 500)

    return app

if __name__ == "__main__":
    app = create_app()
    print("\n⚠️  IMPORTANT: Access this app at http://localhost:5000")
    print("   (WebAuthn requires a secure context: localhost or https)\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
