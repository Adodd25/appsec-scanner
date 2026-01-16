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
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID detected"
    },
    "AWS Secret Key": {
        "pattern": r"aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "description": "AWS Secret Access Key detected"
    },
    "GitHub Token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
        "severity": "critical",
        "description": "GitHub Personal Access Token detected"
    },
    "Generic API Key": {
        "pattern": r"api[_-]?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z]{32,})['\"]",
        "severity": "high",
        "description": "Generic API key detected"
    },
    "Private Key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private cryptographic key detected"
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "high",
        "description": "Slack token detected"
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "high",
        "description": "Google API key detected"
    },
    "Stripe API Key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "severity": "critical",
        "description": "Stripe Live API key detected"
    },
    "Password in URL": {
        "pattern": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}",
        "severity": "high",
        "description": "Password in URL detected"
    },
    "Generic Secret": {
        "pattern": r"(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "medium",
        "description": "Potential hardcoded secret detected"
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
        "severity": "high",
        "description": "JWT token detected"
    },
    "Twilio API Key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio API Key detected"
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "severity": "high",
        "description": "SendGrid API Key detected"
    },
    "Mailgun API Key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key detected"
    },
    "Database Connection String": {
        "pattern": r"(mongodb|mysql|postgres|postgresql)://[^\s]{10,}",
        "severity": "high",
        "description": "Database connection string detected"
    },
    "Firebase URL": {
        "pattern": r".*firebaseio\.com",
        "severity": "medium",
        "description": "Firebase URL detected"
    },
    "OAuth Token": {
        "pattern": r"access[_-]?token['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-._~+/]{20,})['\"]",
        "severity": "high",
        "description": "OAuth access token detected"
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


def scan_file_for_secrets(file_path: Path) -> List[Dict]:
    """Scan a single file for secrets"""
    secrets_found = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            # Skip comments (basic detection)
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for secret_type, config in SECRET_PATTERNS.items():
                pattern = config['pattern']
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
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
    
    except Exception as e:
        # Skip files that can't be read
        pass
    
    return secrets_found


def scan_directory_for_secrets(target_path: Path) -> Dict:
    """Scan directory for secrets"""
    all_secrets = []
    files_scanned = 0
    
    if target_path.is_file():
        if should_scan_file(target_path):
            all_secrets.extend(scan_file_for_secrets(target_path))
            files_scanned = 1
    else:
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and should_scan_file(file_path):
                secrets = scan_file_for_secrets(file_path)
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
