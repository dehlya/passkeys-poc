
# Security Policy

## 🎓 Educational Project Notice

This is an **educational proof-of-concept** developed for IT Security coursework. It is designed to demonstrate WebAuthn/FIDO2 concepts and is **NOT intended for production use**.

## Supported Versions

This project is maintained as a learning resource. Security updates are provided on a best-effort basis.

| Version | Supported |
| ------- | --------- |
| main    | :white_check_mark: |

## Known Limitations (By Design)

The following are intentional limitations for this educational POC:

- No rate limiting on authentication endpoints
- Basic session management (no rotation)
- SQLite database (not for production scale)
- HTTP allowed for local development
- No comprehensive audit logging
- Single-server architecture only

**These are NOT vulnerabilities** - they're educational simplifications. Production systems should address all of these.

## Reporting a Vulnerability

If you discover a security vulnerability in this educational project:

### For Educational/Learning Issues

- Open a GitHub Issue with the `security` label
- Describe the issue and its educational impact
- Suggest improvements or learning opportunities

### For Actual Security Concerns

If you find a vulnerability that could impact users running this POC:

1. **DO NOT** open a public issue
2. Email the maintainer directly (see GitHub profile)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

### Response Timeline

- **Acknowledgment**: Within 1 week
- **Assessment**: Within 2 weeks
- **Fix (if applicable)**: Within 4 weeks
- **Disclosure**: After fix is merged

## Security Best Practices for Users

If you're using this POC for learning:

### DO:

- Run in isolated development environments only
- Use `.env.example` to configure safely
- Keep dependencies updated
- Study the code to understand security patterns
- Compare with production-grade implementations

### DON'T:

- Deploy to public internet without hardening
- Store real user credentials
- Use production API keys
- Assume this code is production-ready
- Skip reading the security comments in the code

## Security Features Implemented

This POC **does** implement several real security practices:

- CSRF protection on state-changing endpoints
- Content Security Policy (CSP) headers
- Parameterized SQL queries (SQL injection prevention)
- Challenge replay protection
- Origin binding verification
- Signature counter validation
- Secure session cookie configuration
- Input validation

These are **intentional teaching examples** of production patterns.

## Learning Resources

To better understand security in authentication systems:

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [WebAuthn Security Considerations](https://www.w3.org/TR/webauthn/#sctn-security-considerations)
- [FIDO Alliance Specifications](https://fidoalliance.org/specifications/)

## Attribution

If you improve the security of this project, please contribute back so others can learn!

---
*Security through education*
 