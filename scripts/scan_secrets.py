#!/usr/bin/env python3
"""
Secret Scanner
Detects hardcoded secrets, API keys, passwords, and tokens in code
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Tuple


# Comprehensive secret patterns
# case_sensitive: True means match exactly as written (for tokens with specific prefixes)
# case_sensitive: False means match case-insensitively (for keywords like "password")
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID detected",
        "case_sensitive": True  # AWS keys are always uppercase AKIA
    },
    "AWS Secret Key": {
        "pattern": r"aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "description": "AWS Secret Access Key detected",
        "case_sensitive": False  # "aws" keyword can vary
    },
    "GitHub Token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
        "severity": "critical",
        "description": "GitHub Personal Access Token detected",
        "case_sensitive": True  # GitHub tokens have exact prefixes
    },
    "Generic API Key": {
        "pattern": r"api[_-]?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z]{32,})['\"]",
        "severity": "high",
        "description": "Generic API key detected",
        "case_sensitive": False  # "api_key" can be any case
    },
    "Private Key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private cryptographic key detected",
        "case_sensitive": True  # PEM headers are exact
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "high",
        "description": "Slack token detected",
        "case_sensitive": True  # Slack tokens have exact prefix
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google API key detected",
        "case_sensitive": True  # Google keys start with exact prefix
    },
    "Stripe API Key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "severity": "critical",
        "description": "Stripe Live API key detected",
        "case_sensitive": True  # Stripe keys have exact prefix
    },
    "Password in URL": {
        "pattern": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}",
        "severity": "high",
        "description": "Password in URL detected",
        "case_sensitive": False
    },
    "Generic Secret": {
        "pattern": r"(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "medium",
        "description": "Potential hardcoded secret detected",
        "case_sensitive": False  # Keywords like "password" can be any case
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
        "severity": "high",
        "description": "JWT token detected",
        "case_sensitive": True  # JWT always starts with eyJ (base64 of "{")
    },
    "Twilio API Key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio API Key detected",
        "case_sensitive": True  # Twilio keys have exact prefix
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "severity": "high",
        "description": "SendGrid API Key detected",
        "case_sensitive": True  # SendGrid keys have exact prefix
    },
    "Mailgun API Key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key detected",
        "case_sensitive": True  # Mailgun keys have exact prefix
    },
    "Database Connection String": {
        "pattern": r"(mongodb|mysql|postgres|postgresql)://[^\s]{10,}",
        "severity": "high",
        "description": "Database connection string detected",
        "case_sensitive": False  # URL schemes can vary
    },
    "Firebase URL": {
        "pattern": r"[a-zA-Z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "description": "Firebase URL detected",
        "case_sensitive": False
    },
    "OAuth Token": {
        "pattern": r"access[_-]?token['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-._~+/]{20,})['\"]",
        "severity": "high",
        "description": "OAuth access token detected",
        "case_sensitive": False  # "access_token" keyword can be any case
    }
}

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.php',
    '.c', '.cpp', '.h', '.hpp', '.cs', '.sh', '.bash', '.zsh',
    '.yaml', '.yml', '.json', '.xml', '.env', '.config', '.conf',
    '.txt', '.md', '.rst', '.properties', '.ini', '.toml'
}

# Files/directories to skip
SKIP_PATTERNS = {
    'node_modules', '.git', '.svn', '__pycache__', 'venv', 'env',
    '.venv', 'dist', 'build', '.pytest_cache', 'coverage',
    '.mypy_cache', '.tox', 'htmlcov', 'site-packages'
}


def should_scan_file(file_path: Path) -> bool:
    """Determine if file should be scanned"""
    # Check if in skip directory
    for part in file_path.parts:
        if part in SKIP_PATTERNS:
            return False
    
    # Check extension
    return file_path.suffix.lower() in SCANNABLE_EXTENSIONS


def is_comment_line(line: str, file_ext: str) -> bool:
    """
    Check if a line is a comment based on file extension.
    Returns True for full-line comments only (not inline comments).
    """
    stripped = line.strip()
    if not stripped:
        return False

    # Common comment prefixes by language
    if stripped.startswith('#'):  # Python, Ruby, Shell, YAML
        return True
    if stripped.startswith('//'):  # JavaScript, TypeScript, Java, C, Go
        return True
    if stripped.startswith('--'):  # SQL, Lua
        return True
    if stripped.startswith(';'):  # INI, Assembly
        return True
    if stripped.startswith('/*'):  # Multi-line comment start (C-style)
        return True
    if stripped.startswith('*'):  # Likely inside multi-line comment
        return True
    if stripped.startswith('REM ') or stripped.upper().startswith('REM '):  # Batch
        return True

    # Python/JS docstrings - basic detection
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return True

    return False


def scan_file_for_secrets(file_path: Path, warnings: List[str] = None) -> List[Dict]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to file to scan
        warnings: Optional list to append warning messages to
    """
    secrets_found = []
    file_ext = file_path.suffix.lower()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            # Skip comment lines
            if is_comment_line(line, file_ext):
                continue

            for secret_type, config in SECRET_PATTERNS.items():
                pattern = config['pattern']
                # Use case-sensitive or case-insensitive matching based on pattern config
                flags = 0 if config.get('case_sensitive', True) else re.IGNORECASE
                matches = re.finditer(pattern, line, flags)

                for match in matches:
                    # Extract matched secret (truncate for safety)
                    matched_text = match.group(0)
                    if len(matched_text) > 50:
                        display_text = matched_text[:50] + "..."
                    else:
                        display_text = matched_text

                    secrets_found.append({
                        'type': secret_type,
                        'file': str(file_path),
                        'line': line_num,
                        'severity': config['severity'],
                        'description': config['description'],
                        'matched': display_text,
                        'line_content': line.strip()[:100]
                    })

    except PermissionError:
        if warnings is not None:
            warnings.append(f"Permission denied: {file_path}")
    except UnicodeDecodeError as e:
        if warnings is not None:
            warnings.append(f"Encoding error in {file_path}: {e}")
    except Exception as e:
        if warnings is not None:
            warnings.append(f"Could not read {file_path}: {e}")

    return secrets_found


def scan_directory_for_secrets(target_path: Path) -> Dict:
    """Scan directory for secrets"""
    all_secrets = []
    files_scanned = 0
    warnings = []

    if target_path.is_file():
        if should_scan_file(target_path):
            all_secrets.extend(scan_file_for_secrets(target_path, warnings))
            files_scanned = 1
    else:
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and should_scan_file(file_path):
                secrets = scan_file_for_secrets(file_path, warnings)
                all_secrets.extend(secrets)
                files_scanned += 1

    # Categorize by severity
    severity_counts = {
        'critical': len([s for s in all_secrets if s['severity'] == 'critical']),
        'high': len([s for s in all_secrets if s['severity'] == 'high']),
        'medium': len([s for s in all_secrets if s['severity'] == 'medium']),
        'low': len([s for s in all_secrets if s['severity'] == 'low'])
    }

    return {
        'success': True,
        'tool': 'Secret Scanner',
        'target': str(target_path),
        'files_scanned': files_scanned,
        'files_with_errors': len(warnings),
        'warnings': warnings,
        'secrets': all_secrets,
        'total_secrets': len(all_secrets),
        'severity_breakdown': severity_counts
    }


def format_results(results: Dict) -> str:
    """Format scan results for display"""
    output = []

    output.append(f"\n{'='*70}")
    output.append(f"🔐 Secret Scanner Results")
    output.append(f"{'='*70}")
    output.append(f"Target: {results['target']}")
    output.append(f"Files Scanned: {results['files_scanned']}")
    if results.get('files_with_errors', 0) > 0:
        output.append(f"Files Skipped (errors): {results['files_with_errors']}")
    output.append(f"Secrets Found: {results['total_secrets']}")
    
    severity = results['severity_breakdown']
    output.append(f"\nSeverity Breakdown:")
    output.append(f"  🔴 CRITICAL: {severity['critical']}")
    output.append(f"  🟠 HIGH:     {severity['high']}")
    output.append(f"  🟡 MEDIUM:   {severity['medium']}")
    output.append(f"  🟢 LOW:      {severity['low']}")
    
    if results['secrets']:
        output.append(f"\n{'─'*70}")
        output.append("Detected Secrets:")
        output.append(f"{'─'*70}")
        
        # Group by file
        secrets_by_file = {}
        for secret in results['secrets']:
            file_path = secret['file']
            if file_path not in secrets_by_file:
                secrets_by_file[file_path] = []
            secrets_by_file[file_path].append(secret)
        
        for file_path, secrets in secrets_by_file.items():
            output.append(f"\n📁 {file_path}")
            for secret in secrets:
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(secret['severity'], '⚪')
                
                output.append(f"  {severity_icon} Line {secret['line']}: {secret['type']}")
                output.append(f"     {secret['description']}")
                output.append(f"     Matched: {secret['matched']}")
                
        output.append(f"\n{'─'*70}")
        output.append("⚠️  IMPORTANT: Review all detected secrets immediately!")
        output.append("   • Rotate any exposed credentials")
        output.append("   • Remove secrets from code")
        output.append("   • Use environment variables or secret managers")
        output.append("   • Check git history for leaked secrets")
    else:
        output.append("\n✅ No secrets detected!")

    # Display warnings for files that couldn't be scanned
    warnings = results.get('warnings', [])
    if warnings:
        output.append(f"\n{'─'*70}")
        output.append(f"⚠️  Warnings ({len(warnings)} files could not be scanned):")
        for warning in warnings[:10]:  # Limit to first 10
            output.append(f"   • {warning}")
        if len(warnings) > 10:
            output.append(f"   ... and {len(warnings) - 10} more")

    output.append(f"\n{'='*70}\n")

    return "\n".join(output)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_secrets.py <path_to_scan>")
        print("\nScans code for hardcoded secrets, API keys, passwords, and tokens")
        sys.exit(1)
    
    target_path = Path(sys.argv[1])
    
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(2)
    
    print(f"🔍 Scanning for secrets in: {target_path}")
    results = scan_directory_for_secrets(target_path)
    print(format_results(results))
    
    # Exit with appropriate code
    if results['total_secrets'] > 0:
        sys.exit(1)  # Secrets found
    else:
        sys.exit(0)  # Clean scan
