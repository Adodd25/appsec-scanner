#!/usr/bin/env python3
"""
Python Security Scanner using Bandit
Scans Python code for common security vulnerabilities
"""

import subprocess
import json
import sys
from pathlib import Path


def scan_python_code(target_path):
    """
    Scan Python code using Bandit security linter
    
    Args:
        target_path: Path to Python file or directory to scan
    
    Returns:
        dict: Scan results including vulnerabilities found
    """
    target = Path(target_path)
    
    if not target.exists():
        return {
            "success": False,
            "error": f"Target path does not exist: {target_path}"
        }
    
    # Check if bandit is installed
    try:
        subprocess.run(
            ["bandit", "--version"],
            capture_output=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "success": False,
            "error": "Bandit is not installed. Install with: pip install bandit"
        }
    
    # Run bandit scan
    cmd = [
        "bandit",
        "-r" if target.is_dir() else "",
        "-f", "json",
        str(target)
    ]
    cmd = [c for c in cmd if c]  # Remove empty strings
    
    result = None
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        # Check for errors in stderr (Bandit may output warnings/errors there)
        stderr_output = result.stderr.strip() if result.stderr else ""
        if stderr_output and result.returncode not in (0, 1):
            # Return code 0 = no issues, 1 = issues found, other = error
            return {
                "success": False,
                "error": f"Bandit error: {stderr_output}",
                "exit_code": result.returncode
            }

        # Bandit returns non-zero exit code when vulnerabilities found
        # Parse JSON output
        output = json.loads(result.stdout) if result.stdout else {}

        vulnerabilities = output.get("results", [])
        metrics = output.get("metrics", {})

        response = {
            "success": True,
            "tool": "Bandit",
            "target": str(target),
            "vulnerabilities": vulnerabilities,
            "total_issues": len(vulnerabilities),
            "severity_breakdown": _categorize_by_severity(vulnerabilities),
            "metrics": metrics
        }

        # Include stderr warnings if any (non-fatal)
        if stderr_output:
            response["warnings"] = stderr_output

        return response

    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Failed to parse Bandit output: {e}",
            "raw_output": result.stdout if result else None,
            "raw_stderr": result.stderr if result else None
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Scan failed: {str(e)}",
            "raw_stderr": result.stderr if result else None
        }


def _categorize_by_severity(vulnerabilities):
    """Categorize vulnerabilities by severity level"""
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for vuln in vulnerabilities:
        severity = vuln.get("issue_severity", "UNKNOWN").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    return severity_counts


def scan_python_dependencies(target_path):
    """
    Scan Python dependencies for known vulnerabilities using pip-audit.

    Args:
        target_path: Path to directory containing requirements.txt or pyproject.toml

    Returns:
        dict: Audit results with vulnerabilities
    """
    target = Path(target_path)

    # Find requirements files
    req_files = []
    if target.is_file() and target.name in ['requirements.txt', 'pyproject.toml']:
        req_files.append(target)
    elif target.is_dir():
        for name in ['requirements.txt', 'requirements-dev.txt', 'pyproject.toml']:
            req_file = target / name
            if req_file.exists():
                req_files.append(req_file)

    if not req_files:
        return {
            "success": True,
            "tool": "pip-audit",
            "vulnerabilities": [],
            "total_issues": 0,
            "message": "No requirements.txt or pyproject.toml found"
        }

    # Check if pip-audit is installed
    try:
        subprocess.run(
            ["pip-audit", "--version"],
            capture_output=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "success": False,
            "error": "pip-audit is not installed. Install with: pip install pip-audit"
        }

    all_vulns = []

    for req_file in req_files:
        try:
            # Run pip-audit with JSON output
            cmd = ["pip-audit", "--format", "json"]

            if req_file.name == 'requirements.txt':
                cmd.extend(["--requirement", str(req_file)])
            else:
                # For pyproject.toml, run in directory
                cmd.extend(["--path", str(req_file.parent)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )

            if result.stdout:
                audit_data = json.loads(result.stdout)

                # pip-audit returns list of dependencies with vulns
                for dep in audit_data:
                    if dep.get("vulns"):
                        for vuln in dep["vulns"]:
                            # Map CVSS to severity
                            cvss = vuln.get("fix_versions", [])
                            vuln_id = vuln.get("id", "UNKNOWN")

                            # Determine severity from vuln ID prefix or aliases
                            severity = "medium"
                            aliases = vuln.get("aliases", [])
                            if any("GHSA" in a for a in aliases):
                                # GitHub Security Advisories - check if critical
                                severity = "high"
                            if "CRITICAL" in vuln_id.upper():
                                severity = "critical"

                            all_vulns.append({
                                "package": dep.get("name", "unknown"),
                                "installed_version": dep.get("version", "unknown"),
                                "vulnerability_id": vuln_id,
                                "severity": severity,
                                "description": vuln.get("description", f"Vulnerability {vuln_id}"),
                                "fix_versions": vuln.get("fix_versions", []),
                                "aliases": aliases,
                                "source_file": str(req_file)
                            })

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"pip-audit timed out scanning {req_file}"
            }
        except json.JSONDecodeError as e:
            # pip-audit may return non-JSON on error
            pass
        except Exception as e:
            pass  # Continue with other files

    return {
        "success": True,
        "tool": "pip-audit",
        "vulnerabilities": all_vulns,
        "total_issues": len(all_vulns),
        "files_scanned": [str(f) for f in req_files]
    }


def format_results(results):
    """Format scan results for readable output"""
    if not results.get("success"):
        return f"❌ Error: {results.get('error')}"
    
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"🔍 Python Security Scan Results ({results['tool']})")
    output.append(f"{'='*60}")
    output.append(f"Target: {results['target']}")
    output.append(f"Total Issues Found: {results['total_issues']}")
    
    severity = results['severity_breakdown']
    output.append(f"\nSeverity Breakdown:")
    output.append(f"  🔴 HIGH:   {severity['HIGH']}")
    output.append(f"  🟡 MEDIUM: {severity['MEDIUM']}")
    output.append(f"  🟢 LOW:    {severity['LOW']}")
    
    if results['vulnerabilities']:
        output.append(f"\n{'─'*60}")
        output.append("Vulnerabilities:")
        output.append(f"{'─'*60}")
        
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            output.append(f"\n[{i}] {vuln.get('test_id', 'N/A')}: {vuln.get('test_name', 'Unknown')}")
            output.append(f"    Severity: {vuln.get('issue_severity', 'N/A')}")
            output.append(f"    Confidence: {vuln.get('issue_confidence', 'N/A')}")
            output.append(f"    File: {vuln.get('filename', 'N/A')}:{vuln.get('line_number', 'N/A')}")
            output.append(f"    Issue: {vuln.get('issue_text', 'N/A')}")
            
            if vuln.get('code'):
                output.append(f"    Code: {vuln['code'].strip()}")
    else:
        output.append("\n✅ No vulnerabilities found!")
    
    output.append(f"\n{'='*60}\n")
    
    return "\n".join(output)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Python Security Scanner")
    parser.add_argument("scan_type", nargs="?", default="code",
                        choices=["code", "deps"],
                        help="'code' for Bandit scan or 'deps' for pip-audit")
    parser.add_argument("path", help="Path to Python file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    if args.scan_type == "deps":
        results = scan_python_dependencies(args.path)
        if args.json:
            print(json.dumps(results))
        else:
            # Simple text output for deps
            if results.get("success"):
                print(f"\n{'='*60}")
                print(f"📦 Python Dependency Security Scan (pip-audit)")
                print(f"{'='*60}")
                print(f"Vulnerabilities Found: {results['total_issues']}")
                for vuln in results.get('vulnerabilities', []):
                    print(f"  - {vuln['package']} {vuln['installed_version']}: {vuln['vulnerability_id']}")
            else:
                print(f"Error: {results.get('error')}")
    else:
        results = scan_python_code(args.path)
        if args.json:
            print(json.dumps(results))
        else:
            print(format_results(results))

    # Exit with appropriate code
    if results.get("success") and results.get("total_issues", 0) > 0:
        sys.exit(1)  # Vulnerabilities found
    elif not results.get("success"):
        sys.exit(2)  # Scan failed
    else:
        sys.exit(0)  # Clean scan
