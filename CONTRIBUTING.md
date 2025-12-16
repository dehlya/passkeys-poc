# Contributing to Passkeys Protocol Auditing Lab

Thank you for your interest in improving this educational project!

## About This Project

This is an **educational proof-of-concept** for IT Security coursework. Contributions that enhance learning outcomes or demonstrate security concepts are especially welcome.

## Good Contribution Areas

### 1. Educational Enhancements

- Additional documentation or explanations
- More detailed protocol visualizations
- Step-by-step guides or tutorials
- Comparison with other authentication methods

### 2. Security Demonstrations

- New threat model scenarios
- Additional security header examples
- Attack demonstrations (for learning)
- Security testing examples

### 3. Code Quality

- Bug fixes
- Code comments and documentation
- Test coverage improvements
- Performance optimizations (if they aid understanding)

### 4. Feature Additions

- Additional vendor comparisons
- More protocol analysis tools
- Enhanced forensic capabilities
- Better error messages for learning

## Out of Scope

Since this is an educational POC, these are **intentionally not included**:

- Production deployment features
- Enterprise-scale architecture
- Complex dependency management
- Advanced DevOps tooling

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/dehlya/passkeys-poc.git
cd passkeys-poc
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

Use prefixes:
- `feature/` - New functionality
- `fix/` - Bug fixes
- `docs/` - Documentation only
- `edu/` - Educational enhancements

### 3. Make Your Changes

- Write clear, commented code
- Follow existing code style
- Add explanatory comments for security decisions
- Update documentation if needed

### 4. Test Your Changes

```bash
# Install dependencies
pip install -r src/requirements.txt

# Run the application
cd src
python app.py

# Test manually in browser
# (Automated tests coming soon!)
```

### 5. Commit with Clear Messages

```bash
git commit -m "feat: add explanation for challenge generation"
git commit -m "fix: correct CSRF token validation logic"
git commit -m "docs: clarify WebAuthn flow in README"
```

### 6. Push & Create PR

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub with:
- **Description**: What does this change do?
- **Why**: What problem does it solve or what does it teach?
- **Testing**: How did you test it?
- **Learning Value**: What can students learn from this?

## Code Style Guidelines

### Python

- Follow PEP 8
- Use descriptive variable names
- Add comments explaining **why**, not just **what**
- Security decisions should be documented

Example:
```python
# SECURITY: Pop challenge first to prevent replay attacks
# See: NIST SP 800-63B Section 5.2.9
challenge = session.pop("challenge", None)
```

### JavaScript

- Use vanilla JS (no frameworks for simplicity)
- Add comments for WebAuthn API usage
- Explain security-relevant logic

### HTML/CSS

- Keep it simple and readable
- Maintain accessibility
- Educational clarity over visual flair

## Testing Guidelines

For now, manual testing is sufficient:
1. Test both Protocol Auditing and Vendor modes
2. Verify protocol trace outputs correctly
3. Check that security features work as expected
4. Test on multiple browsers if possible

Future: We'd love automated tests! Consider contributing:
- Playwright E2E tests
- Python unit tests for WebAuthn logic
- Security testing examples

## Documentation Standards

- Use clear, educational language
- Assume reader has basic web dev knowledge
- Explain security concepts, don't just implement them
- Link to relevant specs or resources

## Review Process

1. Maintainer will review within 1-2 weeks
2. May ask questions or request changes
3. Once approved, will be merged
4. Your contribution helps others learn!

## Ideas for Contributions

Not sure where to start? Try these:

- [ ] Add a "Security Concepts" page explaining key terms
- [ ] Create a video tutorial or screenshots
- [ ] Write a comparison with OAuth/OIDC
- [ ] Add more detailed error messages with learning tips
- [ ] Document the threat model more thoroughly
- [ ] Add accessibility improvements
- [ ] Create a Docker setup for easier testing
- [ ] Add internationalization (i18n)

## Reporting Bugs

Found a bug? Great! Here's how to report it:

1. Check if it's already reported in Issues
2. Open a new issue with:
   - **Title**: Brief description
   - **Steps to Reproduce**: Numbered steps
   - **Expected Behavior**: What should happen?
   - **Actual Behavior**: What actually happens?
   - **Environment**: OS, browser, Python version
   - **Screenshots**: If applicable

## Questions?

- Open a GitHub Discussion
- Comment on relevant issues
- Reach out via the contact info in README

## Recognition

All contributors will be:
- Listed in the project README
- Credited in release notes
- Thanked profusely!

## Code of Conduct

Be respectful, constructive, and remember: **everyone is here to learn**.

---

**Thank you for helping make authentication security more accessible to learners!**
