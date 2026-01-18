#!/usr/bin/env python3
"""
Semgrep Security Scanner
Advanced SAST with data flow analysis, taint tracking, and multi-language support.
Significantly more powerful than pattern-based scanners.
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import Dict, List, Any


def check_semgrep_installed() -> bool:
    """Check if Semgrep is available"""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_semgrep_version() -> str:
    """Get Semgrep version for reporting"""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def scan_with_semgrep(target_path: str, config: str = "auto") -> Dict[str, Any]:
    """
    Run Semgrep security scan on target path.

    Args:
        target_path: Path to file or directory to scan
        config: Semgrep config to use. Options:
            - "auto": Uses Semgrep's auto-detection (recommended)
            - "p/security-audit": Comprehensive security ruleset
            - "p/owasp-top-ten": OWASP Top 10 rules
            - "p/python": Python-specific rules
            - "p/javascript": JavaScript-specific rules
            - Custom path to rules file

    Returns:
        dict: Scan results with vulnerabilities
    """
    target = Path(target_path)

    if not target.exists():
        return {
            "success": False,
            "error": f"Target path does not exist: {target_path}"
        }

    if not check_semgrep_installed():
        return {
            "success": False,
            "error": "Semgrep is not installed. Install with: pip install semgrep"
        }

    # Build Semgrep command
    # Using --config=auto gets security rules automatically based on detected languages
    cmd = [
        "semgrep",
        "--config", config,
        "--json",
        "--no-git-ignore",  # Don't use .gitignore (we handle exclusions ourselves)
        "--metrics", "off",  # Don't send metrics
        "--quiet",  # Reduce noise
        str(target)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout for large codebases
        )

        # Semgrep exit codes:
        # 0 = success, no findings
        # 1 = findings found
        # 2 = fatal error
        # 3 = invalid config
        # 4 = target parse error (partial results may exist)

        if result.returncode in [2, 3]:
            return {
                "success": False,
                "error": f"Semgrep error (code {result.returncode}): {result.stderr}",
                "exit_code": result.returncode
            }

        # Parse JSON output
        try:
            semgrep_data = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Failed to parse Semgrep output: {e}",
                "raw_output": result.stdout[:1000] if result.stdout else None
            }

        # Extract results
        findings = semgrep_data.get("results", [])
        errors = semgrep_data.get("errors", [])

        # Transform findings to our vulnerability format
        vulnerabilities = []
        for finding in findings:
            vuln = transform_finding(finding)
            vulnerabilities.append(vuln)

        # Categorize by severity
        severity_counts = categorize_by_severity(vulnerabilities)

        response = {
            "success": True,
            "tool": "Semgrep",
            "version": get_semgrep_version(),
            "config": config,
            "target": str(target),
            "vulnerabilities": vulnerabilities,
            "total_issues": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "paths_scanned": semgrep_data.get("paths", {}).get("scanned", []),
            "files_scanned": len(semgrep_data.get("paths", {}).get("scanned", []))
        }

        # Include errors/warnings if any
        if errors:
            response["errors"] = [
                {"message": e.get("message", str(e)), "path": e.get("path", "")}
                for e in errors[:10]  # Limit to 10 errors
            ]

        return response

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Semgrep scan timed out after 10 minutes"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Semgrep scan failed: {str(e)}"
        }


def transform_finding(finding: Dict) -> Dict[str, Any]:
    """
    Transform a Semgrep finding to our standard vulnerability format.

    Semgrep findings have rich metadata including:
    - Data flow traces (for taint analysis)
    - CWE mappings
    - OWASP categories
    - References
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})

    # Map Semgrep severity to our standard
    semgrep_severity = extra.get("severity", "WARNING").upper()
    severity = map_severity(semgrep_severity)

    # Extract location
    start = finding.get("start", {})
    end = finding.get("end", {})

    # Build description with metadata
    message = extra.get("message", "Security issue detected")

    # Add CWE if available
    cwe = metadata.get("cwe", [])
    if cwe:
        if isinstance(cwe, list):
            cwe_str = ", ".join(str(c) for c in cwe)
        else:
            cwe_str = str(cwe)
        message = f"{message} (CWE: {cwe_str})"

    # Add OWASP category if available
    owasp = metadata.get("owasp", [])
    if owasp:
        if isinstance(owasp, list):
            owasp_str = ", ".join(str(o) for o in owasp)
        else:
            owasp_str = str(owasp)
        message = f"{message} [OWASP: {owasp_str}]"

    # Extract data flow information for taint findings
    dataflow_trace = extra.get("dataflow_trace", {})
    taint_source = None
    taint_sink = None

    if dataflow_trace:
        # Semgrep provides source/sink for taint analysis
        source = dataflow_trace.get("taint_source", {})
        if source:
            source_loc = source.get("location", {})
            taint_source = {
                "file": source_loc.get("path", ""),
                "line": source_loc.get("start", {}).get("line", 0),
                "content": source.get("content", "")
            }

        sink = dataflow_trace.get("taint_sink", {})
        if sink:
            sink_loc = sink.get("location", {})
            taint_sink = {
                "file": sink_loc.get("path", ""),
                "line": sink_loc.get("start", {}).get("line", 0),
                "content": sink.get("content", "")
            }

    vuln = {
        "rule_id": finding.get("check_id", "unknown"),
        "title": metadata.get("shortDescription", finding.get("check_id", "Security Issue")),
        "severity": severity,
        "message": message,
        "description": extra.get("message", ""),
        "file": finding.get("path", "unknown"),
        "line": start.get("line", 0),
        "column": start.get("col", 1),
        "end_line": end.get("line", 0),
        "end_column": end.get("col", 1),
        "code": extra.get("lines", ""),
        "fix": extra.get("fix", ""),
        "references": metadata.get("references", []),
        "cwe": cwe,
        "owasp": owasp,
        "confidence": metadata.get("confidence", "MEDIUM"),
        "category": metadata.get("category", "security"),
        "technology": metadata.get("technology", []),
        "is_taint_finding": bool(dataflow_trace)
    }

    # Add taint information if present
    if taint_source:
        vuln["taint_source"] = taint_source
    if taint_sink:
        vuln["taint_sink"] = taint_sink

    return vuln


def map_severity(semgrep_severity: str) -> str:
    """Map Semgrep severity levels to our standard"""
    severity_map = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
        "INVENTORY": "low",
        "EXPERIMENT": "low"
    }
    return severity_map.get(semgrep_severity.upper(), "medium")


def categorize_by_severity(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """Categorize vulnerabilities by severity level"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "medium").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["medium"] += 1

    return counts


def scan_with_multiple_configs(target_path: str, configs: List[str] = None) -> Dict[str, Any]:
    """
    Run Semgrep with multiple rule configurations for comprehensive coverage.

    Args:
        target_path: Path to scan
        configs: List of configs to use. Default uses security-focused rulesets.

    Returns:
        Combined results from all configs
    """
    if configs is None:
        # Default to comprehensive security scanning
        configs = [
            "auto",  # Auto-detect language and apply relevant security rules
        ]

    all_vulnerabilities = []
    all_errors = []
    files_scanned = set()

    for config in configs:
        result = scan_with_semgrep(target_path, config)

        if result.get("success"):
            all_vulnerabilities.extend(result.get("vulnerabilities", []))
            files_scanned.update(result.get("paths_scanned", []))
            if result.get("errors"):
                all_errors.extend(result["errors"])
        elif "not installed" not in result.get("error", ""):
            all_errors.append({"message": result.get("error", "Unknown error"), "config": config})

    # Deduplicate vulnerabilities by fingerprint
    seen = set()
    unique_vulns = []
    for vuln in all_vulnerabilities:
        fingerprint = f"{vuln['file']}:{vuln['line']}:{vuln['rule_id']}"
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique_vulns.append(vuln)

    return {
        "success": True,
        "tool": "Semgrep",
        "version": get_semgrep_version(),
        "configs_used": configs,
        "vulnerabilities": unique_vulns,
        "total_issues": len(unique_vulns),
        "severity_breakdown": categorize_by_severity(unique_vulns),
        "files_scanned": len(files_scanned),
        "errors": all_errors if all_errors else None
    }


def format_results(results: Dict) -> str:
    """Format scan results for readable output"""
    if not results.get("success"):
        return f"Error: {results.get('error')}"

    output = []
    output.append(f"\n{'='*70}")
    output.append(f"Semgrep Security Scan Results")
    output.append(f"{'='*70}")
    output.append(f"Tool Version: {results.get('version', 'unknown')}")
    output.append(f"Config: {results.get('config', results.get('configs_used', 'auto'))}")
    output.append(f"Files Scanned: {results.get('files_scanned', 0)}")
    output.append(f"Total Issues: {results['total_issues']}")

    severity = results.get('severity_breakdown', {})
    output.append(f"\nSeverity Breakdown:")
    output.append(f"  Critical: {severity.get('critical', 0)}")
    output.append(f"  High:     {severity.get('high', 0)}")
    output.append(f"  Medium:   {severity.get('medium', 0)}")
    output.append(f"  Low:      {severity.get('low', 0)}")

    if results['vulnerabilities']:
        output.append(f"\n{'-'*70}")
        output.append("Findings:")
        output.append(f"{'-'*70}")

        # Group by severity
        for sev in ['critical', 'high', 'medium', 'low']:
            sev_vulns = [v for v in results['vulnerabilities'] if v.get('severity') == sev]
            if sev_vulns:
                output.append(f"\n[{sev.upper()}]")
                for vuln in sev_vulns[:10]:  # Limit per severity
                    output.append(f"\n  Rule: {vuln['rule_id']}")
                    output.append(f"  File: {vuln['file']}:{vuln['line']}")
                    output.append(f"  Message: {vuln['description'][:100]}...")

                    if vuln.get('is_taint_finding'):
                        output.append(f"  [TAINT ANALYSIS] Data flow vulnerability detected")
                        if vuln.get('taint_source'):
                            output.append(f"    Source: {vuln['taint_source']['file']}:{vuln['taint_source']['line']}")
                        if vuln.get('taint_sink'):
                            output.append(f"    Sink: {vuln['taint_sink']['file']}:{vuln['taint_sink']['line']}")

                    if vuln.get('cwe'):
                        output.append(f"  CWE: {vuln['cwe']}")

                if len(sev_vulns) > 10:
                    output.append(f"\n  ... and {len(sev_vulns) - 10} more {sev} findings")
    else:
        output.append("\nNo security issues found!")

    output.append(f"\n{'='*70}\n")

    return "\n".join(output)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Semgrep Security Scanner")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("--config", default="auto",
                       help="Semgrep config (auto, p/security-audit, p/owasp-top-ten, etc.)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    results = scan_with_semgrep(args.path, args.config)

    if args.json:
        print(json.dumps(results))
    else:
        print(format_results(results))

    # Exit codes
    if results.get("success") and results.get("total_issues", 0) > 0:
        sys.exit(1)  # Vulnerabilities found
    elif not results.get("success"):
        sys.exit(2)  # Scan failed
    else:
        sys.exit(0)  # Clean scan
