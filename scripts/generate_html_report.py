#!/usr/bin/env python3
"""
HTML Report Generator
Creates beautiful, interactive HTML security reports
"""

import json
from datetime import datetime
from pathlib import Path


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; font-size: 1.1em; }}
        .timestamp {{ opacity: 0.8; font-size: 0.9em; margin-top: 10px; }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border-left: 4px solid #667eea;
        }}
        .card h3 {{ color: #667eea; margin-bottom: 15px; font-size: 1.1em; }}
        .card .number {{ font-size: 2.5em; font-weight: bold; color: #2c3e50; }}
        .card .label {{ color: #7f8c8d; font-size: 0.9em; }}
        
        .severity-critical {{ color: #e74c3c; }}
        .severity-high {{ color: #e67e22; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #3498db; }}
        
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }}
        
        .vulnerability {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #e74c3c;
        }}
        .vulnerability.high {{ border-left-color: #e67e22; }}
        .vulnerability.medium {{ border-left-color: #f39c12; }}
        .vulnerability.low {{ border-left-color: #3498db; }}
        
        .vulnerability-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .vulnerability-title {{ font-weight: bold; font-size: 1.1em; }}
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #fee; color: #e74c3c; }}
        .severity-badge.high {{ background: #fef5e7; color: #e67e22; }}
        .severity-badge.medium {{ background: #fef9e7; color: #f39c12; }}
        .severity-badge.low {{ background: #ebf5fb; color: #3498db; }}
        
        .vulnerability-details {{ margin: 15px 0; color: #555; }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .file-location {{ color: #7f8c8d; font-size: 0.9em; margin: 5px 0; }}
        
        .chart-container {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }}
        
        .progress-bar {{
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .progress-critical {{ background: #e74c3c; }}
        .progress-high {{ background: #e67e22; }}
        .progress-medium {{ background: #f39c12; }}
        .progress-low {{ background: #3498db; }}
        
        .recommendations {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .recommendations h3 {{ color: #2e7d32; margin-bottom: 10px; }}
        .recommendations ul {{ margin-left: 20px; }}
        .recommendations li {{ margin: 8px 0; }}
        
        .risk-score {{
            text-align: center;
            padding: 30px;
        }}
        .risk-number {{
            font-size: 4em;
            font-weight: bold;
            margin: 20px 0;
        }}
        .risk-high {{ color: #e74c3c; }}
        .risk-medium {{ color: #f39c12; }}
        .risk-low {{ color: #27ae60; }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            margin-top: 50px;
        }}
        
        @media print {{
            body {{ background: white; }}
            .section, .card {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Assessment Report</h1>
            <div class="subtitle">{project_name}</div>
            <div class="timestamp">Generated: {timestamp}</div>
        </header>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{total_vulns}</div>
                <div class="label">Security Issues Found</div>
            </div>
            <div class="card">
                <h3>Critical Issues</h3>
                <div class="number severity-critical">{critical_count}</div>
                <div class="label">Immediate Action Required</div>
            </div>
            <div class="card">
                <h3>Files Scanned</h3>
                <div class="number">{files_scanned}</div>
                <div class="label">Code Files Analyzed</div>
            </div>
            <div class="card">
                <h3>Risk Score</h3>
                <div class="number {risk_class}">{risk_score}</div>
                <div class="label">Overall Security Rating</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2>Severity Distribution</h2>
            {severity_chart}
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{executive_summary}</p>
            
            <div class="risk-score">
                <h3>Overall Risk Assessment</h3>
                <div class="risk-number {risk_class}">{risk_score}/100</div>
                <p>{risk_description}</p>
            </div>
        </div>
        
        {vulnerability_sections}
        
        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                <h3>Immediate Actions</h3>
                <ul>
                    {recommendations}
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>Scan Details</h2>
            <p><strong>Target:</strong> {target_path}</p>
            <p><strong>Scan Tools:</strong> {scan_tools}</p>
            <p><strong>Scan Duration:</strong> {scan_duration}</p>
            <p><strong>Languages Detected:</strong> {languages}</p>
        </div>
    </div>
    
    <footer>
        <p>Generated by Application Security Scanner</p>
        <p>Report generated at {timestamp}</p>
    </footer>
</body>
</html>
"""


def calculate_risk_score(scan_results):
    """Calculate overall risk score (0-100, higher is worse)"""
    score = 0
    
    # Weight by severity
    critical = scan_results.get('critical_count', 0)
    high = scan_results.get('high_count', 0)
    medium = scan_results.get('medium_count', 0)
    low = scan_results.get('low_count', 0)
    
    score += critical * 25  # Each critical adds 25 points
    score += high * 10      # Each high adds 10 points
    score += medium * 3     # Each medium adds 3 points
    score += low * 1        # Each low adds 1 point
    
    # Cap at 100
    return min(score, 100)


def get_risk_description(score):
    """Get risk description based on score"""
    if score >= 75:
        return "🔴 Critical - Immediate remediation required"
    elif score >= 50:
        return "🟠 High - Address vulnerabilities within 24-48 hours"
    elif score >= 25:
        return "🟡 Medium - Plan remediation within 1-2 weeks"
    else:
        return "🟢 Low - Minor issues, address during regular maintenance"


def get_risk_class(score):
    """Get CSS class for risk score"""
    if score >= 75:
        return "risk-high"
    elif score >= 50:
        return "risk-medium"
    else:
        return "risk-low"


def generate_severity_chart(critical, high, medium, low):
    """Generate HTML for severity chart"""
    total = critical + high + medium + low
    if total == 0:
        return "<p>No vulnerabilities detected ✅</p>"
    
    chart_html = []
    
    if critical > 0:
        pct = (critical / total) * 100
        chart_html.append(f'<div class="progress-bar">')
        chart_html.append(f'  <div class="progress-fill progress-critical" style="width: {pct}%">')
        chart_html.append(f'    Critical: {critical} ({pct:.1f}%)')
        chart_html.append(f'  </div>')
        chart_html.append(f'</div>')
    
    if high > 0:
        pct = (high / total) * 100
        chart_html.append(f'<div class="progress-bar">')
        chart_html.append(f'  <div class="progress-fill progress-high" style="width: {pct}%">')
        chart_html.append(f'    High: {high} ({pct:.1f}%)')
        chart_html.append(f'  </div>')
        chart_html.append(f'</div>')
    
    if medium > 0:
        pct = (medium / total) * 100
        chart_html.append(f'<div class="progress-bar">')
        chart_html.append(f'  <div class="progress-fill progress-medium" style="width: {pct}%">')
        chart_html.append(f'    Medium: {medium} ({pct:.1f}%)')
        chart_html.append(f'  </div>')
        chart_html.append(f'</div>')
    
    if low > 0:
        pct = (low / total) * 100
        chart_html.append(f'<div class="progress-bar">')
        chart_html.append(f'  <div class="progress-fill progress-low" style="width: {pct}%">')
        chart_html.append(f'    Low: {low} ({pct:.1f}%)')
        chart_html.append(f'  </div>')
        chart_html.append(f'</div>')
    
    return '\n'.join(chart_html)


def generate_vulnerability_section(vulnerabilities, title):
    """Generate HTML for vulnerability section"""
    if not vulnerabilities:
        return ""
    
    html = [f'<div class="section"><h2>{title}</h2>']
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'medium').lower()
        vuln_html = f'''
        <div class="vulnerability {severity}">
            <div class="vulnerability-header">
                <div class="vulnerability-title">{vuln.get('title', 'Security Issue')}</div>
                <span class="severity-badge {severity}">{severity}</span>
            </div>
            <div class="vulnerability-details">
                <p>{vuln.get('description', '')}</p>
                <div class="file-location">📁 {vuln.get('file', 'Unknown')}:{vuln.get('line', '?')}</div>
            </div>
            {f'<div class="code-block">{vuln.get("code", "")}</div>' if vuln.get('code') else ''}
            {f'<div class="recommendations"><h3>Fix:</h3><p>{vuln.get("fix", "")}</p></div>' if vuln.get('fix') else ''}
        </div>
        '''
        html.append(vuln_html)
    
    html.append('</div>')
    return '\n'.join(html)


def generate_html_report(scan_results, output_path='security-report.html'):
    """Generate comprehensive HTML security report"""
    
    # Calculate metrics
    critical = scan_results.get('critical_count', 0)
    high = scan_results.get('high_count', 0)
    medium = scan_results.get('medium_count', 0)
    low = scan_results.get('low_count', 0)
    total_vulns = critical + high + medium + low
    
    risk_score = calculate_risk_score(scan_results)
    risk_class = get_risk_class(risk_score)
    risk_description = get_risk_description(risk_score)
    
    # Generate executive summary
    exec_summary = f"Security scan completed on {scan_results.get('project_name', 'Unknown Project')}. "
    if total_vulns == 0:
        exec_summary += "✅ No vulnerabilities detected. The codebase appears to follow security best practices."
    else:
        exec_summary += f"Identified {total_vulns} security issues across the codebase. "
        if critical > 0:
            exec_summary += f"⚠️ {critical} critical vulnerabilities require immediate attention. "
        exec_summary += "Review detailed findings below and implement recommended fixes."
    
    # Generate recommendations
    recommendations = []
    if critical > 0:
        recommendations.append("🔴 Address all CRITICAL vulnerabilities immediately (within 24 hours)")
    if high > 0:
        recommendations.append("🟠 Remediate HIGH severity issues within 48 hours")
    if scan_results.get('secrets_found', 0) > 0:
        recommendations.append("🔐 Rotate any exposed credentials and remove from codebase")
    if scan_results.get('outdated_dependencies', 0) > 0:
        recommendations.append("📦 Update vulnerable dependencies to patched versions")
    if medium > 0:
        recommendations.append("🟡 Plan fixes for MEDIUM severity issues within 1-2 weeks")
    recommendations.append("✅ Integrate security scanning into CI/CD pipeline")
    recommendations.append("📚 Review OWASP Top 10 guidance for development team")
    
    recommendations_html = '\n'.join([f'<li>{r}</li>' for r in recommendations])
    
    # Generate severity chart
    severity_chart = generate_severity_chart(critical, high, medium, low)
    
    # Generate vulnerability sections
    vuln_sections = []
    if scan_results.get('critical_vulnerabilities'):
        vuln_sections.append(generate_vulnerability_section(
            scan_results['critical_vulnerabilities'],
            "🔴 Critical Vulnerabilities"
        ))
    if scan_results.get('high_vulnerabilities'):
        vuln_sections.append(generate_vulnerability_section(
            scan_results['high_vulnerabilities'],
            "🟠 High Severity Issues"
        ))
    if scan_results.get('medium_vulnerabilities'):
        vuln_sections.append(generate_vulnerability_section(
            scan_results['medium_vulnerabilities'],
            "🟡 Medium Severity Issues"
        ))
    
    vulnerability_sections = '\n'.join(vuln_sections)
    
    # Fill template
    html_content = HTML_TEMPLATE.format(
        project_name=scan_results.get('project_name', 'Unknown Project'),
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total_vulns=total_vulns,
        critical_count=critical,
        files_scanned=scan_results.get('files_scanned', 0),
        risk_score=risk_score,
        risk_class=risk_class,
        risk_description=risk_description,
        severity_chart=severity_chart,
        executive_summary=exec_summary,
        vulnerability_sections=vulnerability_sections,
        recommendations=recommendations_html,
        target_path=scan_results.get('target_path', 'Unknown'),
        scan_tools=scan_results.get('scan_tools', 'Bandit, ESLint, npm audit'),
        scan_duration=scan_results.get('scan_duration', 'N/A'),
        languages=scan_results.get('languages', 'Python, JavaScript')
    )
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path


if __name__ == "__main__":
    # Example usage
    example_results = {
        'project_name': 'My Application',
        'target_path': '/path/to/project',
        'files_scanned': 150,
        'critical_count': 2,
        'high_count': 5,
        'medium_count': 10,
        'low_count': 8,
        'scan_tools': 'Bandit, ESLint, npm audit, Secret Scanner',
        'scan_duration': '45 seconds',
        'languages': 'Python, JavaScript, TypeScript',
        'critical_vulnerabilities': [
            {
                'title': 'SQL Injection Vulnerability',
                'severity': 'critical',
                'description': 'Unsanitized user input in SQL query allows injection attacks',
                'file': 'app/database.py',
                'line': 45,
                'code': 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))'
            }
        ]
    }
    
    output = generate_html_report(example_results)
    print(f"HTML report generated: {output}")
