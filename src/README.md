# Source Code – WebAuthn Backend

This directory contains the Flask backend implementing the WebAuthn
registration and authentication ceremonies for the Passkeys Proof of Concept.

The code is written to prioritize **clarity, correctness, and auditability**
over performance or production abstraction.

---

## Key Files

- **app.py**  
  Main Flask application handling routing, session management, and WebAuthn
  verification logic.

- **poc_data.db**  
  SQLite database storing:
  - user identifiers
  - credential IDs
  - public keys
  - signature counters (`sign_count`)

- **templates/**  
  Jinja2 templates for the login interface, dashboard, and workflow inspection.

- **static/**  
  Frontend JavaScript and CSS, including the protocol trace (“X-Ray”) logic.

---

## WebAuthn Flow Overview

### Registration
- `/webauthn/register/start`  
  Generates registration options and a cryptographically secure challenge.
- `/webauthn/register/finish`  
  Verifies attestation, origin binding, and stores public key material.

### Authentication
- `/webauthn/login/start`  
  Generates a fresh authentication challenge.
- `/webauthn/login/finish`  
  Verifies the signature, origin, and updates the signature counter.

---

## Security Mechanisms Implemented

- Single-use challenge enforcement via session storage
- Origin and RP ID verification
- Signature counter replay protection
- CSRF protection on state-changing endpoints
- Parameterized SQL queries (SQL injection prevention)
- Cache-control headers to prevent stale authenticated sessions

---

## Scope

This codebase is intended for educational and analytical purposes.
It does not include production hardening such as rate limiting,
HTTPS enforcement, or enterprise IAM integration.
