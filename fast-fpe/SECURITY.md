# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `fast-fpe`, please report it responsibly.

**Email:** security@syncoda.net

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

**Please include:**
- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fix (if applicable)

## Disclosure Timeline

- We will acknowledge receipt of your report within **48 hours**
- We will provide an initial assessment within **7 days**
- We aim to release a fix within **90 days** of the initial report
- We will coordinate with you on the public disclosure timeline

## Scope

This policy covers:
- The `fast-core` crate (FAST algorithm implementation)
- The `fast-ff1` crate (FF1 implementation)
- The `fast-migrate` crate (migration utility)
- The `fast-fpe` Python bindings
- The `syncoda-fast` integration layer

## Security Considerations

### Implementation Status

This is a **new implementation** of the FAST format-preserving encryption scheme
published at ASIACRYPT 2021. It has **not** undergone third-party security review
or formal verification.

### What FAST Is NOT

- FAST is **not** a NIST-standardized algorithm
- FAST has **not** been approved for PCI DSS compliance
- This implementation has **not** been FIPS 140-validated

### Known Limitations

- Side-channel resistance: S-box lookups use constant-time linear scans for
  small radixes, but this has not been verified under all compiler optimizations
- The security proof in the FAST paper relies partly on empirical analysis
  of the SPN construction's diffusion properties
- No formal verification of the implementation has been performed

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
