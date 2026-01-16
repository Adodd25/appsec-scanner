# Application Security Scanner Skill - Enhanced Edition

An enterprise-grade Claude skill for comprehensive security scanning and vulnerability assessment of Python, JavaScript, and Node.js applications. Features advanced reporting, secret detection, risk scoring, and OWASP Top 10 coverage.

## Features

- 🔍 **Multi-Tool Automated Security Scanning**
  - Python code analysis using Bandit
  - JavaScript/Node.js code analysis using ESLint with security plugins
  - Node.js dependency vulnerability scanning using npm audit
  - **NEW: Secret detection** for 15+ types of credentials
  
- 🛡️ **OWASP Top 10 Coverage**
  - All 10 major web application security risks
  - Detailed detection patterns and remediation examples
  
- 📊 **Advanced Reporting & Integration**
  - **NEW: Interactive HTML reports** with charts and visualizations
  - **NEW: SARIF format** for GitHub Security tab
  - JSON output for programmatic analysis
  - Risk scoring and prioritization
  - Configuration file support
  
- 🚀 **Multi-Language Support**
  - Python
  - JavaScript
  - Node.js
  - TypeScript

## What's New in Enhanced Edition

### Secret Detection
Automatically detects hardcoded secrets in your codebase:
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- API Keys (Generic, Google, Stripe, SendGrid, Twilio, Mailgun)
- Private cryptographic keys
- Database connection strings (MongoDB, MySQL, PostgreSQL)
- JWT tokens, OAuth tokens
- Passwords in code and URLs

### Interactive HTML Reports
Beautiful, professional security reports with:
- Executive summary with risk scoring
- Interactive severity distribution charts
- Detailed vulnerability listings with code snippets
- Actionable remediation recommendations
- Risk assessment and prioritization

### SARIF Format
Generate SARIF (Static Analysis Results Interchange Format) output:
- Upload directly to GitHub Security tab
- Compatible with security platforms
- Standard format for vulnerability tracking

### Configuration System
Customize scans with `.appsec-config.yml`:
- Enable/disable specific scanners
- Set severity thresholds
- Configure output formats
- Define file inclusion/exclusion patterns
- Set risk scoring weights
- Suppress false positives

### Risk Scoring
Intelligent risk assessment system:
- Weighted severity scoring
- Overall risk rating (0-100)
- Automated prioritization
- CI/CD failure thresholds

## Installation

### Prerequisites

- Python 3.7+
- Node.js 14+ and npm (for JavaScript/Node.js scanning)

### Install Security Tools

```bash
# Python security tools
pip install bandit pyyaml --break-system-packages

# JavaScript/Node.js security tools (run in your project directory)
npm install --save-dev eslint eslint-plugin-security

# Optional: Additional Python security tools
pip install safety pip-audit --break-system-packages
```

### Install the Skill

1. Download the `appsec-scanner.skill` file
2. In Claude.ai or the Claude app, go to Settings → Skills
3. Click "Add Skill" and upload the `.skill` file
4. Enable the skill for use

Alternatively, if you're using this skill manually without the Claude skill system:

```bash
# Clone or download this repository
git clone https://github.com/yourusername/appsec-scanner-skill.git
cd appsec-scanner-skill
```

## Quick Start

### Run a Comprehensive Security Scan

```bash
python scripts/run_security_scan.py /path/to/your/project
```

This will:
- Automatically detect Python, JavaScript, and Node.js code
- Run appropriate security scanners
- Detect hardcoded secrets and credentials  
- Generate comprehensive security reports (HTML, JSON, SARIF)
- Calculate risk score and prioritize findings

### Advanced Usage

**Secret Detection Only:**
```bash
python scripts/scan_secrets.py /path/to/code
```

**With Configuration File:**
```bash
# Create .appsec-config.yml in your project
python scripts/run_security_scan.py . --config .appsec-config.yml
```

**Custom Output Formats:**
```bash
# Generate HTML and SARIF reports
python scripts/run_security_scan.py . --format html,sarif

# HTML report opens in browser for interactive viewing
# SARIF report can be uploaded to GitHub Security tab
```

### Language-Specific Scans

**Scan Python code only:**
```bash
python scripts/scan_python.py /path/to/python/code
```

**Scan JavaScript code:**
```bash
python scripts/scan_javascript.py code /path/to/javascript/code
```

**Audit Node.js dependencies:**
```bash
python scripts/scan_javascript.py npm /path/to/nodejs/project
```

### Scan Options

Skip specific scan types if needed:

```bash
# Skip dependency scanning
python scripts/run_security_scan.py ./project --skip-dependencies

# Skip Python scanning
python scripts/run_security_scan.py ./project --skip-python

# Skip JavaScript scanning
python scripts/run_security_scan.py ./project --skip-javascript
```

## Usage with Claude

Once the skill is installed, you can use it naturally in conversation:

**Example prompts:**
- "Scan my project for security vulnerabilities"
- "Review this code for OWASP Top 10 issues"
- "Check my Node.js dependencies for known CVEs"
- "Generate a security assessment report for my Flask app"
- "What security issues are in this authentication module?"

Claude will automatically:
1. Run the appropriate security scans
2. Analyze the results
3. Consult OWASP Top 10 and vulnerability pattern references
4. Generate detailed remediation recommendations

## What Gets Scanned

### Python Security Checks (Bandit)
- Hardcoded passwords and secrets
- SQL injection vulnerabilities
- Use of insecure functions (pickle, eval, exec)
- Weak cryptographic practices
- Command injection risks
- Path traversal vulnerabilities
- And 40+ other security issues

### JavaScript/Node.js Security Checks (ESLint)
- XSS (Cross-Site Scripting) risks
- Regex Denial of Service (ReDoS)
- Unsafe regular expressions
- Use of eval() and Function()
- Insecure random number generation
- And more security patterns

### Dependency Vulnerabilities (npm audit)
- Known CVEs in npm packages
- Severity levels (Critical, High, Moderate, Low)
- Available security updates
- Transitive dependency issues

## CI/CD Integration

### GitHub Actions

Add this to `.github/workflows/security.yml`:

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
      
      - name: Install security tools
        run: |
          pip install bandit
          npm install -g eslint eslint-plugin-security
      
      - name: Run security scan
        run: python scripts/run_security_scan.py .
      
      - name: Upload results
        if: failure()
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: security-report.txt
```

### GitLab CI

Add this to `.gitlab-ci.yml`:

```yaml
security_scan:
  image: python:3.9
  before_script:
    - pip install bandit
    - apt-get update && apt-get install -y nodejs npm
    - npm install -g eslint eslint-plugin-security
  script:
    - python scripts/run_security_scan.py .
  artifacts:
    when: on_failure
    paths:
      - security-report.txt
```

## OWASP Top 10 Coverage

This skill provides comprehensive coverage of the OWASP Top 10 (2021):

1. **A01:2021 - Broken Access Control**
2. **A02:2021 - Cryptographic Failures**
3. **A03:2021 - Injection**
4. **A04:2021 - Insecure Design**
5. **A05:2021 - Security Misconfiguration**
6. **A06:2021 - Vulnerable and Outdated Components**
7. **A07:2021 - Identification and Authentication Failures**
8. **A08:2021 - Software and Data Integrity Failures**
9. **A09:2021 - Security Logging and Monitoring Failures**
10. **A10:2021 - Server-Side Request Forgery (SSRF)**

Each vulnerability type includes:
- Detection patterns for Python and JavaScript/Node.js
- Vulnerable vs. secure code examples
- Detailed remediation guidance

## Example Output

```
==================================================================
🛡️  APPLICATION SECURITY SCAN REPORT
==================================================================
Timestamp: 2024-01-15T10:30:00
Target: /home/user/my-app
Scans Performed: Python (Bandit), JavaScript (ESLint), Node.js Dependencies (npm audit)
==================================================================

==================================================================
🔍 Python Security Scan Results (Bandit)
==================================================================
Target: /home/user/my-app
Total Issues Found: 5

Severity Breakdown:
  🔴 HIGH:   2
  🟡 MEDIUM: 2
  🟢 LOW:    1

────────────────────────────────────────────────────────────────
Vulnerabilities:
────────────────────────────────────────────────────────────────

[1] B608: hardcoded_sql_expressions
    Severity: MEDIUM
    Confidence: HIGH
    File: app/database.py:45
    Issue: Possible SQL injection vector through string-based query construction
    Code: cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

[...]
```

## Project Structure

```
appsec-scanner/
├── SKILL.md                           # Comprehensive skill documentation
├── README.md                          # Main documentation
├── INSTALL.md                         # Installation guide
├── CONTRIBUTING.md                    # Contribution guidelines
├── LICENSE.txt                        # MIT License
├── .gitignore                         # Git ignore rules
├── .appsec-config.yml                 # Configuration file template
├── .github/
│   └── workflows/
│       └── security-scan.yml          # GitHub Actions workflow
├── scripts/
│   ├── run_security_scan.py          # 🆕 Enhanced main orchestrator
│   ├── scan_python.py                # Python scanner (Bandit)
│   ├── scan_javascript.py            # JavaScript/Node scanner
│   ├── scan_secrets.py               # 🆕 Secret detection scanner
│   ├── generate_html_report.py       # 🆕 HTML report generator
│   └── generate_sarif.py             # 🆕 SARIF format generator
└── references/
    ├── owasp_top10.md                # OWASP Top 10 reference
    └── vulnerability_patterns.md      # Pattern library
```

## Troubleshooting

### "bandit: command not found"
```bash
pip install bandit --break-system-packages
```

### "eslint: command not found"
```bash
npm install -g eslint eslint-plugin-security
# Or in your project:
npm install --save-dev eslint eslint-plugin-security
```

### No vulnerabilities detected but code seems insecure
- Static analysis tools have limitations
- Manual code review is still necessary
- Consider using multiple scanning tools
- Check for business logic flaws (not detected by scanners)

### Too many false positives
- Review scanner configurations
- Use exclusion rules for test code
- Verify findings manually
- Document confirmed false positives

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Adding New Scanners

To add support for additional languages or tools:

1. Create a new scanner script in `scripts/`
2. Update `run_security_scan.py` to detect and run the new scanner
3. Add language-specific patterns to `references/vulnerability_patterns.md`
4. Update documentation

## Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [ESLint Security Plugin](https://github.com/eslint-community/eslint-plugin-security)
- [npm audit Documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

## License

This project is licensed under the MIT License - see the LICENSE.txt file for details.

## Support

For issues, questions, or feature requests, please:
- Open an issue on GitHub
- Contact the maintainers
- Check the troubleshooting section above

## Changelog

### Version 1.0.0
- Initial release
- Support for Python, JavaScript, and Node.js
- OWASP Top 10 coverage
- Comprehensive vulnerability patterns and remediation guidance
- CI/CD integration examples
