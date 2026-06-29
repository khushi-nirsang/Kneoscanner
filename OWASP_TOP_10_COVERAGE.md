# Kneoscanner OWASP Top 10 Coverage

Kneoscanner includes safe passive checks, same-origin discovery, YAML-based
templates, and authorized active mutation checks for OWASP Top 10 2021 classes.

## Coverage Matrix

### A01:2021 - Broken Access Control
- IDOR probes
- Path traversal and local file inclusion checks
- Broken access control and privilege escalation templates
- Open redirect detection
- Mass assignment and parameter pollution checks

### A02:2021 - Cryptographic Failures
- Sensitive data exposure patterns
- Exposed key, token, credential, and backup file checks
- HTTPS cookie `Secure` flag checks

### A03:2021 - Injection
- SQL injection
- Reflected XSS
- OS command injection
- LDAP injection
- SSTI and advanced SSTI
- XXE probes
- Header injection
- RFI/LFI/path traversal
- Error-based and polyglot injection checks

### A04:2021 - Insecure Design
- CSRF checks on discovered POST forms
- Authentication bypass probes
- Race condition templates
- Missing rate limiting checks

### A05:2021 - Security Misconfiguration
- Missing security headers
- Weak Content Security Policy detection
- Permissive CORS detection
- Server and framework version disclosure checks
- Exposed Swagger/OpenAPI/GraphQL/debug endpoints
- Directory listing and backup/config file exposure

### A06:2021 - Vulnerable and Outdated Components
- Insecure dependency and exposed framework signal checks

### A07:2021 - Identification and Authentication Failures
- Weak/default credential probes
- Authentication bypass checks
- Session cookie `HttpOnly`, `Secure`, and `SameSite` checks

### A08:2021 - Software and Data Integrity Failures
- Insecure deserialization templates
- Backup and configuration exposure checks

### A09:2021 - Security Logging and Monitoring Failures
- Limited direct detection because logging behavior is application-dependent.
  Findings from exposed debug, metrics, and admin surfaces help triage this
  category during review.

### A10:2021 - Server-Side Request Forgery
- SSRF probes with external payload files
- URL parameter mutation during authorized active scans

## Template Groups

Kneoscanner currently ships 36 vulnerability templates:

- Injection: SQLi, XSS, command injection, LDAP, SSTI, XXE, header injection,
  RFI, LFI, path traversal, polyglot, error-based injection, SSRF.
- Access control: IDOR, broken access control, privilege escalation, mass
  assignment, open redirect.
- Authentication: authentication bypass, weak authentication, no rate limiting,
  CSRF.
- Data protection: sensitive data exposure, cryptographic failures, exposed
  sensitive files, JWT token exposure.
- Misconfiguration: API documentation exposure, GraphQL exposure, debug endpoint
  exposure, backup/config exposure, directory listing, CORS misconfiguration.
- Integrity and components: insecure deserialization, insecure dependencies,
  race condition.

## Recommended Usage

```text
./kneoscanner -u https://example.com --profile active --acknowledge-authorization
```

Focus on likely input names when discovery needs help:

```text
./kneoscanner -u https://example.com --profile active --acknowledge-authorization --parameter id,q,search,url,redirect,next,file
```

Use `intrusive` only on systems where you have explicit permission to run
higher-risk mutation checks:

```text
./kneoscanner -u https://example.com --profile intrusive --acknowledge-authorization
```

## Notes

- Passive and safe checks are useful for presentations and low-risk demos.
- Active checks are stronger because they mutate discovered parameters.
- Always review evidence in JSON, HTML, PDF, or SARIF reports before claiming a
  vulnerability is exploitable.
