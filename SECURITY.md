# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in AegisOSINT, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: [security@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

### Responsible Disclosure

We follow responsible disclosure practices:

1. Researchers should give us reasonable time to fix issues
2. We will credit researchers (unless anonymity is preferred)
3. We will not pursue legal action against good-faith researchers

## Security Design Principles

AegisOSINT is built with security-first principles:

### Authorization Enforcement
- First-run authorization acknowledgment required
- Scope validation before ANY network operation
- Hard blocks on out-of-scope targets

### Rate Limiting
- Configurable request budgets
- Burst protection
- Per-module rate limits

### Audit Logging
- All operations logged with timestamps
- Blocked actions recorded
- Full provenance chain for findings

### Data Protection
- No credential storage
- Sensitive data redaction in reports
- No payload or exploit generation

### Safety Guardrails
- Global kill switch capability
- Module-level safety gates
- Maximum risk level enforcement

## Prohibited Use

This tool MUST NOT be used for:

- Unauthorized access to computer systems
- Denial of service attacks
- Credential brute forcing or stuffing
- Exploit development or delivery
- Any activity violating applicable laws

## Security Hardening Tips

When deploying AegisOSINT:

1. **Limit permissions**: Run with minimal required privileges
2. **Secure storage**: Protect the SQLite database file
3. **Network isolation**: Consider running in a dedicated environment
4. **Log retention**: Maintain audit logs per your compliance requirements
5. **Scope files**: Protect scope files as they define attack surface

## Third-Party Dependencies

We regularly audit dependencies for vulnerabilities:

```bash
# Check for vulnerable dependencies
cargo audit
```

Report dependency vulnerabilities through the same process as application vulnerabilities.
