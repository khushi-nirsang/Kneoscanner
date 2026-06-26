# Kneoscanner - Quick Reference Guide

## Quick Start

### Basic Scan
```bash
./neoscanner -u https://target.com
```

### Scan with Threads
```bash
./neoscanner -u https://target.com --threads 50
```

### Scan with Output
```bash
./neoscanner -u https://target.com -o results.json
```

### Scan List of Targets
```bash
./neoscanner -l targets.txt --threads 50
```

### Active Parameter Testing
```bash
./neoscanner -u https://target.com --parameter id,user_id,username
```

---

## All 29 Templates Quick Overview

| # | Template | Category | Severity | Type |
|---|----------|----------|----------|------|
| 1 | SQL Injection | A03 | CRITICAL | Injection |
| 2 | XSS | A03 | MEDIUM | Injection |
| 3 | Command Injection | A03 | CRITICAL | Injection |
| 4 | LDAP Injection | A03 | HIGH | Injection |
| 5 | SSTI | A03 | HIGH | Injection |
| 6 | Advanced SSTI | A03 | CRITICAL | Injection |
| 7 | XXE | A03 | CRITICAL | Injection |
| 8 | Header Injection | A03 | MEDIUM | Injection |
| 9 | RFI | A03 | CRITICAL | Injection |
| 10 | LFI | A01 | HIGH | Access Control |
| 11 | Polyglot Injection | A03 | MEDIUM | Injection |
| 12 | Error-Based Injection | A03 | HIGH | Injection |
| 13 | SSRF | A10 | HIGH | SSRF |
| 14 | Path Traversal | A01 | HIGH | Access Control |
| 15 | IDOR | A01 | HIGH | Access Control |
| 16 | Broken Access Control | A01 | CRITICAL | Access Control |
| 17 | Privilege Escalation | A01 | CRITICAL | Access Control |
| 18 | Mass Assignment | A01 | HIGH | Access Control |
| 19 | Open Redirect | A01 | MEDIUM | Access Control |
| 20 | Authentication Bypass | A07 | CRITICAL | Authentication |
| 21 | Weak Authentication | A07 | HIGH | Authentication |
| 22 | Missing Rate Limiting | A07 | MEDIUM | Authentication |
| 23 | CSRF | A01 | MEDIUM | Design |
| 24 | Sensitive Data Exposure | A02 | HIGH | Cryptography |
| 25 | Cryptographic Failures | A02 | HIGH | Cryptography |
| 26 | Exposed Sensitive Files | A05 | HIGH | Configuration |
| 27 | Insecure Dependencies | A06 | HIGH | Components |
| 28 | Insecure Deserialization | A08 | CRITICAL | Integrity |
| 29 | Race Condition | A08 | HIGH | Integrity |

---

## Severity Levels

- **CRITICAL**: Immediate exploitation risk - Remote Code Execution, Auth Bypass, Privilege Escalation
- **HIGH**: Significant security impact - Data disclosure, Access control bypass
- **MEDIUM**: Moderate risk - Information disclosure, CSRF
- **LOW**: Minor issues - Security misconfiguration
- **INFO**: Informational - No direct security impact

---

## Common Scenarios

### Scan a Web Application
```bash
./neoscanner -u https://vulnerable-app.com --threads 50 --severity critical
```

### Find All Vulnerabilities
```bash
./neoscanner -u https://target.com --threads 50
```

### Test Specific Parameters
```bash
./neoscanner -u https://target.com --parameter user_id,product_id,search
```

### Save Results to File
```bash
./neoscanner -u https://target.com -o scan_results.json --threads 50
```

### High-Volume Scanning
```bash
./neoscanner -l domains.txt --threads 100 -o batch_results.json
```

---

## Understanding Results

### Critical Findings to Address Immediately
- SQL Injection
- Command Injection
- Authentication Bypass
- Privilege Escalation
- Insecure Deserialization
- Remote File Inclusion

### High Priority Issues
- IDOR
- Broken Access Control
- Cryptographic Failures
- XXE
- SSRF
- Weak Authentication
- Path Traversal

### Medium Priority Issues
- XSS
- CSRF
- Open Redirect
- Header Injection
- Missing Rate Limiting

---

## Tips & Tricks

### Performance Optimization
- Use lower threads (25-50) for slow servers
- Use higher threads (75-100) for robust infrastructure
- Combine with crawling for better discovery

### Accuracy Improvement
- Run against known vulnerable applications first
- Compare results with manual testing
- Review HTML reports for detailed evidence

### Testing Strategy
1. Start with discovery (automatic crawling)
2. Identify parameters of interest
3. Run focused tests on key parameters
4. Review high-severity findings first
5. Validate manually with application behavior

---

## Configuration File

Edit `config.yaml` to customize:

```yaml
threads: 25
timeout: 10
verify_ssl: true
follow_redirects: true
max_redirects: 5
retries: 2
retry_delay: 500
max_response_bytes: 2097152
allow_external_urls: false
crawl: true
crawl_max_depth: 3
crawl_max_pages: 100
discover_scripts: true
templates: templates
output: results.json
severity: low
active_parameter_testing: true
max_parameter_mutations: 200
payloads_per_parameter: 5
active_post_form_testing: true
max_post_form_mutations: 50
```

---

## Vulnerability Breakdown by OWASP Category

### A01 - Broken Access Control (7 templates)
- IDOR, Path Traversal, LFI, Open Redirect, Mass Assignment, Broken AC, Priv Escalation

### A02 - Cryptographic Failures (2 templates)
- Sensitive Data Exposure, Cryptographic Failures

### A03 - Injection (11 templates)
- SQLi, XSS, Command Injection, LDAP, SSTI (2), XXE, Header Injection, RFI, Polyglot, Error-Based

### A04 - Insecure Design (2 templates)
- CSRF, Authentication Bypass

### A05 - Security Misconfiguration (1 template)
- Exposed Sensitive Files

### A06 - Vulnerable Components (1 template)
- Insecure Dependencies

### A07 - Auth Failures (3 templates)
- Auth Bypass, Weak Auth, Rate Limiting

### A08 - Data Integrity (2 templates)
- Insecure Deserialization, Race Condition

### A09 - Logging/Monitoring
- Limited (application-dependent)

### A10 - SSRF (1 template)
- SSRF Detection

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No findings | Check target reachability, try increasing threads |
| Slow scanning | Reduce threads, disable crawling for specific domains |
| SSL errors | Set `verify_ssl: false` in config (use caution) |
| Too many false positives | Review matcher conditions in templates |
| Missing headers | Check if target requires specific User-Agent or headers |

---

## Documentation Files

- `README.md` - General information
- `OWASP_TOP_10_COVERAGE.md` - Detailed OWASP mapping
- `IMPLEMENTATION_SUMMARY.md` - Complete implementation details
- This file - Quick reference

---

*Kneoscanner Version: 2.0 - OWASP Top 10 Complete*
*Last Updated: 2026-06-23*
