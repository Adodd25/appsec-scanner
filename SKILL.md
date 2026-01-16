---
name: appsec-scanner
description: Enterprise-grade application security scanner with comprehensive coverage of Python, JavaScript, and Node.js projects. Features include automated vulnerability detection with multiple tools (Bandit, ESLint, npm audit, secret scanner), OWASP Top 10 analysis, secret detection (API keys, passwords, tokens), HTML and SARIF report generation, risk scoring and prioritization, configuration file support, and CI/CD integration. Use this skill when (1) Performing security audits, (2) Evaluating projects for vulnerabilities, (3) Generating professional security reports, (4) Detecting hardcoded secrets and credentials, (5) Getting remediation guidance, (6) Integrating security scanning into CI/CD pipelines, or (7) Producing GitHub Security-compatible SARIF reports.
---

# Application Security Scanner - Enhanced Edition

Enterprise-grade security scanning with advanced features for comprehensive vulnerability assessment and reporting.

## Core Capabilities

1. **Multi-Tool Automated Security Scanning**
   - Python code analysis using Bandit
   - JavaScript/Node.js code analysis using ESLint with security plugins
   - Node.js dependency vulnerability scanning using npm audit
   - **Secret detection** - API keys, passwords, tokens, credentials
   - Multi-language project support

2. **Advanced Reporting & Integration**
   - **HTML reports** with interactive charts and visualizations
   - **SARIF format** for GitHub Security tab integration
   - **JSON output** for programmatic analysis
   - **Risk scoring** and prioritization system
   - **Configuration file** support (.appsec-config.yml)

3. **OWASP Top 10 Coverage**
   - Broken Access Control (A01)
   - Cryptographic Failures (A02)
   - Injection (A03)
   - Insecure Design (A04)
   - Security Misconfiguration (A05)
   - Vulnerable and Outdated Components (A06)
   - Identification and Authentication Failures (A07)
   - Software and Data Integrity Failures (A08)
   - Security Logging and Monitoring Failures (A09)
   - Server-Side Request Forgery (A10)

3. **Detailed Remediation Guidance**
   - Code-specific fix recommendations
   - Secure coding pattern examples
   - Best practices for each vulnerability type

## Quick Start

### Running a Comprehensive Scan

Use the main orchestrator script to scan a project:

```bash
python scripts/run_security_scan.py /path/to/project
```

This automatically:
- Detects project type (Python, JavaScript, Node.js)
- Runs appropriate security scanners
- Generates a comprehensive report

### Language-Specific Scans

**Python Only:**
```bash
python scripts/scan_python.py /path/to/code
```

**JavaScript Code:**
```bash
python scripts/scan_javascript.py code /path/to/code
```

**Node.js Dependencies:**
```bash
python scripts/scan_javascript.py npm /path/to/project
```

### Scan Options

Skip specific scan types:
```bash
python scripts/run_security_scan.py ./project --skip-dependencies
python scripts/run_security_scan.py ./project --skip-python
python scripts/run_security_scan.py ./project --skip-javascript
python scripts/run_security_scan.py ./project --skip-secrets
```

### Advanced Features

**Secret Detection:**
```bash
python scripts/scan_secrets.py /path/to/code
```
Detects 15+ types of hardcoded secrets including:
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- API Keys (Generic, Google, Stripe, etc.)
- Private cryptographic keys
- Database connection strings
- JWT tokens
- OAuth tokens
- Passwords in code and URLs

**Configuration File:**
Create `.appsec-config.yml` in your project root to customize:
- Which scanners to run
- File patterns to include/exclude
- Severity thresholds
- Output formats (text, JSON, HTML, SARIF)
- Risk scoring weights
- False positive suppression

**Multiple Output Formats:**
```bash
# Generate all reports
python scripts/run_security_scan.py . --format html,json,sarif

# HTML report with charts (opens in browser)
# JSON for programmatic analysis
# SARIF for GitHub Security tab
```

## Workflow: Security Evaluation

### Step 1: Initial Scan

1. Identify the target directory (Claude Code folder, project directory, etc.)
2. Run the comprehensive security scan using `run_security_scan.py`
3. Review the output for detected vulnerabilities

### Step 2: Analyze Results

For each vulnerability found:
1. Identify the vulnerability type and severity
2. Review the affected code location
3. Consult reference materials for context:
   - Read `references/owasp_top10.md` for OWASP-specific guidance
   - Read `references/vulnerability_patterns.md` for detailed patterns and fixes

### Step 3: Generate Recommendations

For each vulnerability:
1. Explain the security risk in clear terms
2. Provide the specific code that's vulnerable
3. Show the secure alternative code
4. Reference OWASP category if applicable
5. Explain why the fix works

### Step 4: Create Report

Generate a comprehensive security report including:
- Executive summary of findings
- Vulnerability breakdown by severity (Critical, High, Medium, Low)
- Detailed findings with:
  - File locations
  - Vulnerable code snippets
  - Remediation recommendations
  - OWASP references
- Prioritized action items

## Tool Requirements

### Python Scanning
- **Bandit**: `pip install bandit`
- Scans Python code for common security issues
- Detects: hardcoded passwords, SQL injection risks, use of unsafe functions, etc.

### JavaScript/Node.js Scanning
- **npm audit**: Built into npm (npm 6+)
- Scans dependencies for known CVEs
- **ESLint + security plugin**: `npm install eslint eslint-plugin-security`
- Detects: XSS risks, regex DoS, unsafe regex, etc.

### Secret Detection
- **Built-in pattern matching** (no installation required)
- Detects 15+ types of secrets using regex patterns
- Scans all common file types (.py, .js, .env, .config, .yaml, etc.)

### Report Generation
- **PyYAML**: `pip install pyyaml` (for config file support)
- HTML generation: Built-in (no external dependencies)
- SARIF generation: Built-in (no external dependencies)

### Installation Quick Reference

```bash
# Core scanning tools
pip install bandit pyyaml --break-system-packages

# JavaScript/Node.js tools (in project directory)
npm install --save-dev eslint eslint-plugin-security

# Optional: Additional security tools
pip install safety pip-audit --break-system-packages
```

## Reference Materials

### OWASP Top 10 Guide
`references/owasp_top10.md` contains:
- Detailed descriptions of each OWASP Top 10 vulnerability
- Detection patterns for Python and JavaScript/Node.js
- Vulnerable vs. secure code examples
- Scanning tool recommendations

**When to read**: When encountering OWASP-related vulnerabilities or needing comprehensive security guidance.

### Vulnerability Patterns
`references/vulnerability_patterns.md` contains:
- Common vulnerability patterns across languages
- Detailed remediation examples
- Input validation best practices
- Security headers configuration
- Quick remediation checklist

**When to read**: When providing specific fix recommendations or explaining how to remediate a particular vulnerability type.

## Report Structure Template

```markdown
# Security Assessment Report

## Executive Summary
- Total vulnerabilities: X
- Critical: X | High: X | Medium: X | Low: X
- Primary concerns: [List top 3 issues]

## Scan Details
- Target: [path]
- Scan date: [date]
- Tools used: Bandit, ESLint, npm audit
- Languages detected: Python, JavaScript, Node.js

## Vulnerability Findings

### Critical/High Priority

#### [VULN-001] SQL Injection in login.py
**Severity**: Critical
**OWASP Category**: A03:2021 - Injection
**Location**: `src/auth/login.py:45`

**Vulnerable Code**:
```python
query = f"SELECT * FROM users WHERE username='{username}'"
```

**Issue**: Direct string interpolation allows SQL injection attacks.

**Recommendation**:
```python
query = "SELECT * FROM users WHERE username=%s"
cursor.execute(query, (username,))
```

**Explanation**: Use parameterized queries to prevent SQL injection...

[Continue for each finding]

## Remediation Priority

1. [VULN-001] - Critical SQL Injection - Immediate fix required
2. [VULN-003] - High - Hardcoded API keys - Fix within 24 hours
...

## Dependency Vulnerabilities

[List vulnerable packages with CVE numbers and recommended versions]

## Best Practices Recommendations

[General security improvements beyond specific vulnerabilities]
```

## Common Vulnerability Categories

### Injection Flaws
- SQL Injection
- NoSQL Injection
- Command Injection
- XPath Injection
- LDAP Injection

**Detection**: Look for string concatenation in queries/commands
**Fix**: Use parameterized queries, input validation, safe APIs

### Authentication Issues
- Weak password requirements
- Missing rate limiting
- Session fixation
- Insecure session management

**Detection**: Examine login/auth endpoints
**Fix**: Implement strong password policies, rate limiting, secure session handling

### Cryptographic Issues
- Weak algorithms (MD5, SHA1)
- Hardcoded secrets
- Insecure random number generation
- Missing encryption

**Detection**: Search for deprecated crypto functions, hardcoded strings
**Fix**: Use modern algorithms (bcrypt, Argon2), environment variables, crypto.randomBytes

### Access Control
- Missing authorization checks
- IDOR vulnerabilities
- Privilege escalation
- Path traversal

**Detection**: Review authorization logic
**Fix**: Implement proper access control checks at each endpoint

## Integration with CI/CD

For GitHub Actions integration:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.x'
      
      - name: Install dependencies
        run: |
          pip install bandit
          npm install -g eslint eslint-plugin-security
      
      - name: Run security scan
        run: python scripts/run_security_scan.py .
```

## Best Practices for Security Reviews

1. **Be Systematic**: Review all input points, authentication mechanisms, and data storage
2. **Think Like an Attacker**: Consider how each feature could be misused
3. **Check Third-Party Code**: Dependencies can introduce vulnerabilities
4. **Validate Assumptions**: Don't assume inputs are safe or users are benign
5. **Defense in Depth**: Multiple layers of security are better than one
6. **Fail Securely**: Errors should not expose sensitive information
7. **Keep It Simple**: Complex code is harder to secure

## Interpreting Scan Results

### Severity Levels

- **Critical**: Immediate exploitation possible, high impact (e.g., SQL injection, RCE)
- **High**: Exploitation likely, significant impact (e.g., XSS, authentication bypass)
- **Medium**: Requires specific conditions, moderate impact (e.g., CSRF, information disclosure)
- **Low**: Difficult to exploit or minimal impact (e.g., verbose error messages)

### False Positives

Static analysis tools can generate false positives. Verify findings by:
1. Examining the actual code context
2. Tracing data flow to confirm user input reaches vulnerable code
3. Considering whether the finding is exploitable in practice
4. Documenting false positives for future reference

### Prioritization

Fix vulnerabilities in this order:
1. Critical vulnerabilities in production code
2. High severity issues in authentication/authorization
3. Injection flaws with user input
4. Cryptographic weaknesses
5. Dependency vulnerabilities with available patches
6. Medium/Low severity issues

## Example Usage Scenarios

### Scenario 1: New Project Security Review

```
User: "Please review my Flask application for security vulnerabilities"

Response:
1. Run: python scripts/run_security_scan.py /path/to/flask-app
2. Analyze results focusing on OWASP Top 10
3. Review references/owasp_top10.md for Flask-specific patterns
4. Generate comprehensive report with prioritized fixes
```

### Scenario 2: Dependency Audit

```
User: "Check if my Node.js project has any vulnerable dependencies"

Response:
1. Run: python scripts/scan_javascript.py npm /path/to/project
2. Review npm audit results
3. Identify packages with known CVEs
4. Recommend version upgrades or alternative packages
5. Check for transitive dependencies
```

### Scenario 3: Code Review Focus

```
User: "Review this authentication module for security issues"

Response:
1. Run: python scripts/scan_python.py /path/to/auth/
2. Manual code review focusing on:
   - Password handling
   - Session management
   - Rate limiting
   - Input validation
3. Reference vulnerability_patterns.md for authentication issues
4. Provide specific recommendations with secure code examples
```

## Customization

### Adding Custom Rules

For Python (Bandit):
Create `.bandit` config file:
```yaml
tests: [B201, B301, B302, B303, B304, B305, B306, B307, B308, B309, B310]
exclude_dirs: ['/test']
```

For JavaScript (ESLint):
Extend `.eslintrc.json`:
```json
{
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-regexp": "warn"
  }
}
```

## Troubleshooting

### "Tool not found" errors
- Ensure Bandit is installed: `pip install bandit --break-system-packages`
- Ensure ESLint is available: `npm install eslint eslint-plugin-security`
- Check PATH includes npm global bin directory

### No vulnerabilities detected but code seems insecure
- Static analysis has limitations
- Manual code review is still necessary
- Consider using multiple tools
- Check for business logic flaws (not caught by scanners)

### Too many false positives
- Review and tune scanner configurations
- Use exclusion rules for test/development code
- Verify findings manually
- Document confirmed false positives

## Additional Resources

- OWASP Top 10: https://owasp.org/Top10/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- CWE (Common Weakness Enumeration): https://cwe.mitre.org/
- CVE (Common Vulnerabilities and Exposures): https://cve.mitre.org/
