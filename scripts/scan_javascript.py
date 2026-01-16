#!/usr/bin/env python3
"""
JavaScript/Node.js Security Scanner
Runs npm audit and ESLint with security plugins
"""

import subprocess
import json
import sys
import tempfile
from pathlib import Path


def scan_npm_dependencies(project_path):
    """
    Scan npm dependencies for known vulnerabilities using npm audit
    
    Args:
        project_path: Path to Node.js project (contains package.json)
    
    Returns:
        dict: Audit results
    """
    project = Path(project_path)
    package_json = project / "package.json"
    
    if not package_json.exists():
        return {
            "success": False,
            "error": f"No package.json found in {project_path}"
        }
    
    # Check if npm is installed
    try:
        subprocess.run(
            ["npm", "--version"],
            capture_output=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "success": False,
            "error": "npm is not installed"
        }
    
    try:
        # Run npm audit with JSON output
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=str(project),
            capture_output=True,
            text=True
        )
        
        audit_data = json.loads(result.stdout) if result.stdout else {}
        
        # Extract vulnerability information
        vulnerabilities = audit_data.get("vulnerabilities", {})
        metadata = audit_data.get("metadata", {})
        
        vuln_list = []
        for package_name, vuln_info in vulnerabilities.items():
            vuln_list.append({
                "package": package_name,
                "severity": vuln_info.get("severity", "unknown"),
                "via": vuln_info.get("via", []),
                "range": vuln_info.get("range", "unknown"),
                "fixAvailable": vuln_info.get("fixAvailable", False)
            })
        
        severity_counts = {
            "critical": metadata.get("vulnerabilities", {}).get("critical", 0),
            "high": metadata.get("vulnerabilities", {}).get("high", 0),
            "moderate": metadata.get("vulnerabilities", {}).get("moderate", 0),
            "low": metadata.get("vulnerabilities", {}).get("low", 0)
        }
        
        return {
            "success": True,
            "tool": "npm audit",
            "vulnerabilities": vuln_list,
            "total_issues": metadata.get("vulnerabilities", {}).get("total", 0),
            "severity_breakdown": severity_counts,
            "dependencies": metadata.get("dependencies", 0)
        }
        
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Failed to parse npm audit output: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"npm audit failed: {str(e)}"
        }


def scan_javascript_code(target_path):
    """
    Scan JavaScript code for security issues using ESLint
    Note: Requires ESLint and eslint-plugin-security to be installed
    
    Args:
        target_path: Path to JavaScript file or directory
    
    Returns:
        dict: ESLint scan results
    """
    target = Path(target_path)
    
    if not target.exists():
        return {
            "success": False,
            "error": f"Target path does not exist: {target_path}"
        }
    
    # Check if eslint is available
    try:
        result = subprocess.run(
            ["npx", "eslint", "--version"],
            capture_output=True,
            check=False
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": "ESLint not available. Install with: npm install eslint eslint-plugin-security"
            }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "npx not found. Ensure Node.js/npm is installed"
        }
    
    # Create minimal ESLint config for security scanning
    eslint_config = {
        "plugins": ["security"],
        "extends": ["plugin:security/recommended"],
        "env": {
            "node": True,
            "browser": True,
            "es2021": True
        }
    }

    # Use a unique temporary file to avoid race conditions with concurrent scans
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            prefix='eslint_security_config_',
            delete=False
        ) as config_file:
            json.dump(eslint_config, config_file)
            config_file_path = config_file.name

        # Run ESLint with security plugin
        result = subprocess.run(
            ["npx", "eslint",
             "-c", config_file_path,
             "--format", "json",
             str(target)],
            capture_output=True,
            text=True
        )

        eslint_data = json.loads(result.stdout) if result.stdout else []

        vulnerabilities = []
        total_issues = 0

        for file_result in eslint_data:
            for message in file_result.get("messages", []):
                if "security/" in message.get("ruleId", ""):
                    # ESLint severity: 0=off, 1=warn, 2=error
                    eslint_severity = message.get("severity", 1)
                    if eslint_severity == 2:
                        severity = "high"
                    elif eslint_severity == 1:
                        severity = "medium"
                    else:
                        severity = "low"

                    vulnerabilities.append({
                        "file": file_result.get("filePath", "unknown"),
                        "line": message.get("line", 0),
                        "column": message.get("column", 0),
                        "severity": severity,
                        "message": message.get("message", ""),
                        "ruleId": message.get("ruleId", "")
                    })
                    total_issues += 1

        return {
            "success": True,
            "tool": "ESLint + security plugin",
            "vulnerabilities": vulnerabilities,
            "total_issues": total_issues
        }

    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Failed to parse ESLint output: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"ESLint scan failed: {str(e)}"
        }
    finally:
        # Clean up config file
        try:
            Path(config_file_path).unlink()
        except (NameError, OSError):
            pass  # File may not exist or config_file_path not defined


def format_npm_results(results):
    """Format npm audit results"""
    if not results.get("success"):
        return f"❌ Error: {results.get('error')}"
    
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"📦 npm Dependency Security Scan ({results['tool']})")
    output.append(f"{'='*60}")
    output.append(f"Total Dependencies: {results.get('dependencies', 0)}")
    output.append(f"Total Vulnerabilities: {results['total_issues']}")
    
    severity = results['severity_breakdown']
    output.append(f"\nSeverity Breakdown:")
    output.append(f"  🔴 CRITICAL: {severity['critical']}")
    output.append(f"  🟠 HIGH:     {severity['high']}")
    output.append(f"  🟡 MODERATE: {severity['moderate']}")
    output.append(f"  🟢 LOW:      {severity['low']}")
    
    if results['vulnerabilities']:
        output.append(f"\n{'─'*60}")
        output.append("Vulnerable Packages:")
        output.append(f"{'─'*60}")
        
        for i, vuln in enumerate(results['vulnerabilities'][:20], 1):  # Limit to 20
            output.append(f"\n[{i}] {vuln['package']}")
            output.append(f"    Severity: {vuln['severity'].upper()}")
            output.append(f"    Range: {vuln['range']}")
            output.append(f"    Fix Available: {'✅' if vuln['fixAvailable'] else '❌'}")
            
        if len(results['vulnerabilities']) > 20:
            output.append(f"\n... and {len(results['vulnerabilities']) - 20} more")
    else:
        output.append("\n✅ No vulnerable dependencies found!")
    
    output.append(f"\n{'='*60}\n")
    
    return "\n".join(output)


def format_eslint_results(results):
    """Format ESLint security scan results"""
    if not results.get("success"):
        return f"❌ Error: {results.get('error')}"
    
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"🔍 JavaScript Code Security Scan ({results['tool']})")
    output.append(f"{'='*60}")
    output.append(f"Total Security Issues: {results['total_issues']}")
    
    if results['vulnerabilities']:
        output.append(f"\n{'─'*60}")
        output.append("Security Issues:")
        output.append(f"{'─'*60}")
        
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            output.append(f"\n[{i}] {vuln['ruleId']}")
            output.append(f"    Severity: {vuln['severity'].upper()}")
            output.append(f"    File: {vuln['file']}:{vuln['line']}:{vuln['column']}")
            output.append(f"    Message: {vuln['message']}")
    else:
        output.append("\n✅ No code security issues found!")
    
    output.append(f"\n{'='*60}\n")
    
    return "\n".join(output)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scan_javascript.py <scan_type> <path>")
        print("  scan_type: 'npm' for dependency scan or 'code' for code scan")
        print("  path: project directory (for npm) or file/directory (for code)")
        sys.exit(1)
    
    scan_type = sys.argv[1]
    target_path = sys.argv[2]
    
    if scan_type == "npm":
        results = scan_npm_dependencies(target_path)
        print(format_npm_results(results))
    elif scan_type == "code":
        results = scan_javascript_code(target_path)
        print(format_eslint_results(results))
    else:
        print(f"Invalid scan type: {scan_type}")
        print("Use 'npm' or 'code'")
        sys.exit(1)
    
    # Exit with appropriate code
    if results.get("success") and results.get("total_issues", 0) > 0:
        sys.exit(1)  # Vulnerabilities found
    elif not results.get("success"):
        sys.exit(2)  # Scan failed
    else:
        sys.exit(0)  # Clean scan
