# KNeoScanner - Comprehensive OWASP Top 10 Detection

## Overview
KNeoScanner has been enhanced with comprehensive coverage for all OWASP Top 10 2021 vulnerabilities plus additional injection types and security issues.

## OWASP Top 10 2021 Coverage Matrix

### A01:2021 - Broken Access Control
- ✅ Insecure Direct Object Reference (IDOR) Detection
- ✅ Path Traversal / Directory Traversal
- ✅ Broken Access Control
- ✅ Privilege Escalation
- ✅ Local File Inclusion (LFI)
- ✅ Open Redirect
- ✅ Mass Assignment / Parameter Pollution

### A02:2021 - Cryptographic Failures
- ✅ Cryptographic Failures Detection
- ✅ Sensitive Data Exposure (API Keys, Tokens, Passwords)
- ✅ Exposed Sensitive Files (.env, .git, credentials)

### A03:2021 - Injection
- ✅ SQL Injection (Error-based, Time-based, Union-based)
- ✅ OS Command Injection
- ✅ Cross-Site Scripting (XSS) - Reflected
- ✅ LDAP Injection
- ✅ Server-Side Template Injection (SSTI)
- ✅ Advanced SSTI (Jinja2, Mako, Velocity)
- ✅ XML External Entity (XXE) Injection
- ✅ HTTP Header Injection
- ✅ Remote File Inclusion (RFI)
- ✅ Polyglot / Markup Injection
- ✅ Error-Based Injection Detection

### A04:2021 - Insecure Design
- ✅ CSRF Detection
- ✅ Authentication Bypass
- ✅ Race Condition Detection
- ✅ Missing Rate Limiting

### A05:2021 - Security Misconfiguration
- ✅ Exposed Sensitive Files
- ✅ Missing Security Headers (CSP, X-Frame-Options, etc.)
- ✅ Session Cookie Security (HttpOnly, Secure flags)
- ✅ SSL/TLS Misconfiguration

### A06:2021 - Vulnerable & Outdated Components
- ✅ Insecure Dependencies Detection
- ✅ Outdated Framework/Library Version Detection

### A07:2021 - Identification & Authentication Failures
- ✅ Authentication Bypass
- ✅ Weak Authentication & Default Credentials
- ✅ Missing Rate Limiting
- ✅ Session Management Issues

### A08:2021 - Software & Data Integrity Failures
- ✅ Insecure Deserialization (Java, PHP)
- ✅ Race Condition Detection

### A09:2021 - Logging & Monitoring Failures
- ⚠️ Limited (Application-dependent logging)

### A10:2021 - Server-Side Request Forgery (SSRF)
- ✅ SSRF Detection using external payload files

## Template Directory

### Core Injection Templates (15 templates)
1. **sql-injection.yaml** - SQL Injection variants
2. **xss.yaml** - Reflected XSS
3. **command-injection.yaml** - OS Command Injection
4. **ldap-injection.yaml** - LDAP Injection
5. **ssti.yaml** - Basic SSTI
6. **ssti-advanced.yaml** - Advanced SSTI (Jinja2, Mako, Velocity)
7. **xxe-probe.yaml** - XXE Injection
8. **header-injection.yaml** - HTTP Header Injection
9. **remote-file-inclusion.yaml** - RFI
10. **local-file-inclusion.yaml** - LFI
11. **polyglot-injection.yaml** - Polyglot Injection
12. **error-based-injection.yaml** - Error-Based Injection
13. **ssrf-probe.yaml** - SSRF
14. **path-traversal.yaml** - Path Traversal

### Access Control Templates (5 templates)
1. **idor.yaml** - IDOR Detection
2. **broken-access-control.yaml** - Broken Access Control
3. **privilege-escalation.yaml** - Privilege Escalation
4. **mass-assignment.yaml** - Mass Assignment
5. **open-redirect.yaml** - Open Redirect

### Authentication & Authorization (4 templates)
1. **authentication-bypass.yaml** - Auth Bypass
2. **weak-authentication.yaml** - Weak Auth & Default Credentials
3. **no-rate-limiting.yaml** - Missing Rate Limiting
4. **csrf.yaml** - CSRF Detection

### Data Protection (3 templates)
1. **sensitive-data-exposure.yaml** - Sensitive Data Exposure
2. **cryptographic-failures.yaml** - Cryptographic Failures
3. **exposed-sensitive-files.yaml** - Exposed Config Files

### Components & Configuration (2 templates)
1. **insecure-dependencies.yaml** - Vulnerable Components
2. **insecure-deserialization.yaml** - Deserialization Vulnerabilities

### Design & Concurrency (1 template)
1. **race-condition.yaml** - Race Conditions

## Payload Files

### Located in: `payloads/`

- **command-injection/** - OS command injection payloads
- **path-traversal/** - Directory traversal sequences
- **ldap-injection/** - LDAP filter injection payloads
- **weak-auth/** - Default credentials and weak auth attempts
- **deserialization/** - Java and PHP serialization gadget chains
- **header-injection/** - CRLF injection payloads
- **polyglot/** - Polyglot injection payloads
- **xss/** - XSS reflected payloads (existing)
- **sqli/** - SQL injection payloads (existing)
- **ssti/** - SSTI payloads (existing)
- **rfi/** - Remote file inclusion payloads
- **lfi/** - Local file inclusion payloads
- **error-injection/** - Error-based injection payloads
- **xxe/** - XXE payloads (existing, enhanced)
- **ssrf/** - SSRF payloads (existing)
- **idor/** - IDOR payloads (existing)
- **open-redirect/** - Open redirect payloads (existing)

## Usage Examples

### Scan with all OWASP Top 10 templates
```bash
./neoscanner -u http://target.com --threads 50
```

### Scan specific vulnerabilities with parameter testing
```bash
./neoscanner -u http://target.com --parameter id,name,email --threads 50
```

### Scan with verbose output
```bash
./neoscanner -u http://target.com -o results.json --threads 50
```

### Scan multiple targets
```bash
./neoscanner -l targets.txt --threads 50
```

## Configuration

Edit `config.yaml` to customize:
- Number of threads
- HTTP timeout
- Redirect handling
- TLS verification
- Crawling settings
- Active parameter testing
- POST form testing

## Key Features

1. **Comprehensive Coverage**: 29 vulnerability templates covering all OWASP Top 10
2. **Accurate Detection**: Regex and pattern-based matchers for low false positives
3. **Flexible Payloads**: Extensive payload files for each vulnerability type
4. **Discovery Integration**: Automatic parameter discovery and active testing
5. **Session Management**: Cookie-aware HTTP client
6. **Detailed Reporting**: JSON and HTML reports with evidence

## Enhanced Payloads

Each template includes carefully crafted payloads to detect vulnerabilities:

- **SQL Injection**: Error-based, Time-based, Union-based, Blind SQLi
- **Command Injection**: Shell metacharacters, command substitution, time-based
- **XSS**: Reflective payload detection
- **SSTI**: Template engine expressions for multiple frameworks
- **Path Traversal**: Directory traversal sequences and URL encoding bypasses
- **LDAP**: Filter injection with wildcard and OR conditions
- **XXE**: Entity declaration and file disclosure payloads
- **Deserialization**: Gadget chain and serialization format detection

## Recommendations

1. Run comprehensive scans on staging environments first
2. Use parameter discovery (`--parameter`) to test specific inputs
3. Review results carefully as some may require context validation
4. Check HTML reports for detailed evidence
5. Use thread count based on target capacity (default: 25, max recommended: 100)
6. Enable crawling for comprehensive discovery
7. Test against known vulnerable applications first

## Supported Vulnerability Categories

- Injection Attacks (13 types)
- Broken Access Control (7 types)
- Cryptographic Issues (2 types)
- Weak Authentication (3 types)
- Misconfiguration (3 types)
- Vulnerable Dependencies (1 type)
- Insecure Design (2 types)
- SSRF (1 type)

## Performance Tips

1. Adjust threads based on target: 25-50 for most applications
2. Use crawl_max_pages to limit discovery scope
3. Combine parameters to reduce mutation count
4. Run against high-traffic endpoints last
5. Monitor target resource usage during scans

## Troubleshooting

1. **No findings on known vulnerable app**: Check if target is reachable, try with -c flag
2. **High false positives**: Adjust matcher conditions in templates
3. **Slow scanning**: Reduce threads or crawl depth
4. **TLS errors**: Set verify_ssl to false for testing (use with caution)
5. **Missing headers**: Some payloads require custom headers in tests

---

Last Updated: 2026-06-23
Version: 2.0 with OWASP Top 10 2021 Coverage
