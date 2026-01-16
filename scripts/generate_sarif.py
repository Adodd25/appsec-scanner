#!/usr/bin/env python3
"""
SARIF Format Generator
Generates SARIF (Static Analysis Results Interchange Format) output
Compatible with GitHub Security tab and other security platforms
"""

import json
from datetime import datetime
from pathlib import Path


def generate_sarif_report(scan_results, output_path='security-results.sarif'):
    """
    Generate SARIF format report from scan results
    SARIF spec: https://sarifweb.azurewebsites.net/
    """
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": []
    }
    
    # Create a run for each scan tool
    if scan_results.get('python_vulnerabilities'):
        sarif['runs'].append(create_tool_run(
            tool_name="Bandit",
            tool_version="1.7.5",
            vulnerabilities=scan_results['python_vulnerabilities'],
            target_path=scan_results.get('target_path', '.')
        ))
    
    if scan_results.get('javascript_vulnerabilities'):
        sarif['runs'].append(create_tool_run(
            tool_name="ESLint Security",
            tool_version="1.0.0",
            vulnerabilities=scan_results['javascript_vulnerabilities'],
            target_path=scan_results.get('target_path', '.')
        ))
    
    if scan_results.get('secrets'):
        sarif['runs'].append(create_tool_run(
            tool_name="Secret Scanner",
            tool_version="1.0.0",
            vulnerabilities=scan_results['secrets'],
            target_path=scan_results.get('target_path', '.')
        ))
    
    # Write SARIF file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)
    
    return output_path


def create_tool_run(tool_name, tool_version, vulnerabilities, target_path):
    """Create a SARIF run object for a specific tool"""
    
    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://github.com/appsec-scanner",
                "rules": []
            }
        },
        "results": []
    }
    
    # Track unique rules
    rules_added = set()
    
    for vuln in vulnerabilities:
        rule_id = vuln.get('rule_id', vuln.get('type', 'UNKNOWN'))
        
        # Add rule definition if not already added
        if rule_id not in rules_added:
            run['tool']['driver']['rules'].append({
                "id": rule_id,
                "name": vuln.get('title', rule_id),
                "shortDescription": {
                    "text": vuln.get('description', 'Security vulnerability detected')
                },
                "fullDescription": {
                    "text": vuln.get('description', 'Security vulnerability detected')
                },
                "help": {
                    "text": vuln.get('fix', 'Review and remediate this security issue'),
                    "markdown": vuln.get('fix_markdown', vuln.get('fix', ''))
                },
                "defaultConfiguration": {
                    "level": map_severity_to_level(vuln.get('severity', 'warning'))
                },
                "properties": {
                    "tags": ["security", vuln.get('category', 'general')],
                    "security-severity": str(map_severity_to_score(vuln.get('severity', 'medium')))
                }
            })
            rules_added.add(rule_id)
        
        # Add result
        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(vuln.get('severity', 'warning')),
            "message": {
                "text": vuln.get('message', vuln.get('description', 'Security issue detected'))
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(Path(vuln.get('file', 'unknown')).relative_to(target_path) 
                                  if vuln.get('file') else 'unknown'),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": vuln.get('line', 1),
                        "startColumn": vuln.get('column', 1)
                    }
                }
            }]
        }
        
        # Add code snippet if available
        if vuln.get('code'):
            result['locations'][0]['physicalLocation']['region']['snippet'] = {
                "text": vuln.get('code', '')
            }
        
        # Add fix suggestion if available
        if vuln.get('fix'):
            result['fixes'] = [{
                "description": {
                    "text": vuln.get('fix', '')
                }
            }]
        
        run['results'].append(result)
    
    return run


def map_severity_to_level(severity):
    """Map severity string to SARIF level"""
    severity = str(severity).lower()
    
    if severity in ['critical', 'high']:
        return 'error'
    elif severity == 'medium':
        return 'warning'
    else:
        return 'note'


def map_severity_to_score(severity):
    """Map severity to numeric score (0-10) for security-severity"""
    severity = str(severity).lower()
    
    scores = {
        'critical': 9.5,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.0
    }
    
    return scores.get(severity, 5.0)


if __name__ == "__main__":
    # Example usage
    example_results = {
        'target_path': '/home/user/project',
        'python_vulnerabilities': [
            {
                'rule_id': 'B608',
                'title': 'SQL Injection',
                'description': 'Possible SQL injection vector through string-based query construction',
                'severity': 'high',
                'file': '/home/user/project/app/database.py',
                'line': 45,
                'column': 5,
                'code': 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                'fix': 'Use parameterized queries to prevent SQL injection',
                'category': 'injection'
            }
        ],
        'secrets': [
            {
                'type': 'AWS Access Key',
                'description': 'AWS Access Key ID detected',
                'severity': 'critical',
                'file': '/home/user/project/config.py',
                'line': 12,
                'message': 'Hardcoded AWS credentials found'
            }
        ]
    }
    
    output = generate_sarif_report(example_results)
    print(f"SARIF report generated: {output}")
