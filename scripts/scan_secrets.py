#!/usr/bin/env python3
"""
Secret Scanner
Detects hardcoded secrets, API keys, passwords, and tokens in code
"""

import json
import re
import sys
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
        "pattern": r"(mongodb|mysql|postgres|postgresql)://[^/\s:@]+:[^/\s:@]+@[^\s]+",
        "severity": "high",
        "description": "Database connection string with credentials detected",
        "case_sensitive": False  # URL schemes can vary
    },
    # Note: Firebase URLs (*.firebaseio.com) are NOT secrets - they're public endpoints
    # Only the Firebase Admin SDK private key is sensitive
    "Firebase Private Key": {
        "pattern": r"-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----",
        "severity": "critical",
        "description": "Firebase/GCP service account private key detected",
        "case_sensitive": True
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


def _redact_secret(secret: str, secret_type: str) -> str:
    """
    Redact a secret value, showing only enough to identify the type.
    SECURITY: This prevents accidental exposure of credentials in reports.
    """
    if len(secret) <= 8:
        return f"[{secret_type}: {len(secret)} chars]"

    # Show prefix for identifiable tokens (e.g., "ghp_", "sk_live_", "AKIA")
    prefixes = {
        "GitHub Token": 4,
        "AWS Access Key": 4,
        "Stripe API Key": 8,
        "Slack Token": 4,
        "Google API Key": 4,
        "SendGrid API Key": 3,
        "Twilio API Key": 2,
        "Mailgun API Key": 4,
    }

    prefix_len = prefixes.get(secret_type, 0)
    if prefix_len > 0 and len(secret) > prefix_len + 4:
        return f"{secret[:prefix_len]}{'*' * 8}... ({len(secret)} chars)"

    # For other secrets, just show length
    return f"[{secret_type}: {len(secret)} chars]"


def _redact_line(line: str, secret: str) -> str:
    """
    Redact the secret within a line of code.
    SECURITY: Prevents full secret exposure in line context.
    """
    if not secret or secret not in line:
        return line

    # Replace the secret with a redacted placeholder
    redacted = "[REDACTED]"
    return line.replace(secret, redacted)


class CommentTracker:
    """
    Tracks multi-line comment state across lines for accurate detection.
    Handles C-style /* */ comments and Python docstrings.
    """

    def __init__(self):
        self.in_block_comment = False
        self.in_docstring = False
        self.docstring_char = None  # """ or '''

    def is_comment_or_in_block(self, line: str, file_ext: str) -> bool:
        """
        Check if a line is a comment or inside a multi-line comment block.
        Updates internal state for multi-line tracking.
        """
        stripped = line.strip()
        if not stripped:
            return False

        # Handle Python/JS docstrings (""" or ''')
        if file_ext in ['.py', '.js', '.ts']:
            triple_double = '"""'
            triple_single = "'''"

            if self.in_docstring:
                # Check if docstring ends on this line
                if self.docstring_char in stripped:
                    # Count occurrences - odd means it closes
                    count = stripped.count(self.docstring_char)
                    if count % 2 == 1:
                        self.in_docstring = False
                        self.docstring_char = None
                return True

            # Check if docstring starts
            if triple_double in stripped or triple_single in stripped:
                char = triple_double if triple_double in stripped else triple_single
                count = stripped.count(char)
                if count == 1:
                    # Opens but doesn't close on same line
                    self.in_docstring = True
                    self.docstring_char = char
                    return True
                elif count >= 2:
                    # Opens and closes on same line (or multiple)
                    return True

        # Handle C-style block comments /* */
        if self.in_block_comment:
            if '*/' in stripped:
                self.in_block_comment = False
            return True

        if '/*' in stripped:
            if '*/' not in stripped or stripped.index('/*') > stripped.index('*/'):
                self.in_block_comment = True
            return True

        # Single-line comment prefixes
        if stripped.startswith('#'):  # Python, Ruby, Shell, YAML
            return True
        if stripped.startswith('//'):  # JavaScript, TypeScript, Java, C, Go
            return True
        if stripped.startswith('--'):  # SQL, Lua
            return True
        if stripped.startswith(';'):  # INI, Assembly
            return True
        if stripped.upper().startswith('REM '):  # Batch
            return True

        return False

    def reset(self):
        """Reset state for a new file"""
        self.in_block_comment = False
        self.in_docstring = False
        self.docstring_char = None


def scan_file_for_secrets(file_path: Path, warnings: List[str] = None) -> List[Dict]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to file to scan
        warnings: Optional list to append warning messages to
    """
    secrets_found = []
    file_ext = file_path.suffix.lower()

    # Create a new CommentTracker instance for this file (thread-safe)
    comment_tracker = CommentTracker()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            # Skip comment lines (uses per-file tracker for thread safety)
            if comment_tracker.is_comment_or_in_block(line, file_ext):
                continue

            for secret_type, config in SECRET_PATTERNS.items():
                pattern = config['pattern']
                # Use case-sensitive or case-insensitive matching based on pattern config
                flags = 0 if config.get('case_sensitive', True) else re.IGNORECASE
                matches = re.finditer(pattern, line, flags)

                for match in matches:
                    # SECURITY: Don't expose actual secret values in output
                    # Only show the pattern type and location
                    matched_text = match.group(0)
                    redacted_preview = _redact_secret(matched_text, secret_type)

                    secrets_found.append({
                        'type': secret_type,
                        'file': str(file_path),
                        'line': line_num,
                        'severity': config['severity'],
                        'description': config['description'],
                        'matched': redacted_preview,
                        'line_content': _redact_line(line.strip()[:100], matched_text)
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
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan code for hardcoded secrets, API keys, passwords, and tokens"
    )
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    target_path = Path(args.path)

    if not target_path.exists():
        error_result = {"success": False, "error": f"Path does not exist: {target_path}"}
        if args.json:
            print(json.dumps(error_result))
        else:
            print(f"Error: Path does not exist: {target_path}")
        sys.exit(2)

    if not args.json:
        print(f"🔍 Scanning for secrets in: {target_path}")

    results = scan_directory_for_secrets(target_path)

    if args.json:
        print(json.dumps(results))
    else:
        print(format_results(results))

    # Exit with appropriate code
    if results['total_secrets'] > 0:
        sys.exit(1)  # Secrets found
    else:
        sys.exit(0)  # Clean scan
