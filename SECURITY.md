# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **muhammedyusufoa@gmail.com**

Include:
- Type of vulnerability
- Full paths of affected source files
- Steps to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment

You should receive a response within 48 hours. I'll keep you updated on the fix progress.

## Security Best Practices

When deploying HEX IAM:
- Use strong JWT secrets (minimum 32 characters)
- Cryptographically secure 32 length base64 bytes for encryption
- Enable HTTPS in production
- configure CORS to not use wildcards in production
- Regularly rotate JWT secrets
- Use Redis password authentication
- Enable PostgreSQL SSL connections
- Keep dependencies updated