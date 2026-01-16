#!/usr/bin/env python3
"""
Enhanced Application Security Scanner - Main Orchestrator
Comprehensive security scanning with advanced features:
- Multi-language support (Python, JavaScript, Node.js)
- Secret detection
- HTML and SARIF report generation
- Risk scoring and prioritization
- Configuration file support
- OWASP Top 10 coverage
"""

import copy
import subprocess
import sys
import json
import time
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries. Values from override take precedence.
    Nested dictionaries are merged recursively rather than replaced.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class SecurityScanner:
    def __init__(self, target_path, config_path=None):
        self.target_path = Path(target_path)
        self.start_time = time.time()
        self.config = self.load_config(config_path)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target_path': str(self.target_path),
            'project_name': self.target_path.name,
            'scans_performed': [],
            'all_vulnerabilities': [],
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': [],
            'low_vulnerabilities': [],
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'files_scanned': 0,
            'secrets_found': 0,
            'outdated_dependencies': 0
        }
    
    def load_config(self, config_path=None):
        """Load configuration from file or use defaults"""
        default_config = {
            'scan': {
                'python': True,
                'javascript': True,
                'secrets': True,
                'dependencies': True
            },
            'output': {
                'formats': ['text', 'json', 'html', 'sarif'],
                'json_file': 'security-results.json',
                'html_file': 'security-report.html',
                'sarif_file': 'security-results.sarif',
                'verbose': False
            },
            'severity': {
                'minimum': 'low',
                'fail_on': 'high'
            }
        }
        
        # Try to load config file
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.target_path / '.appsec-config.yml'
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        default_config = deep_merge(default_config, user_config)
                    print(f"✅ Loaded configuration from {config_file}")
            except Exception as e:
                print(f"⚠️  Could not load config file: {e}")
                print("   Using default configuration")

        return default_config
    
    def detect_project_type(self):
        """Detect what types of code/projects exist"""
        project_info = {
            'python': False,
            'javascript': False,
            'nodejs': False,
            'python_files': [],
            'js_files': [],
            'package_json': []
        }
        
        # Search for files
        if self.target_path.is_file():
            if self.target_path.suffix == ".py":
                project_info['python'] = True
                project_info['python_files'].append(str(self.target_path))
            elif self.target_path.suffix in [".js", ".jsx"]:
                project_info['javascript'] = True
                project_info['js_files'].append(str(self.target_path))
        else:
            # Scan directory
            python_files = list(self.target_path.rglob("*.py"))
            if python_files:
                project_info['python'] = True
                project_info['python_files'] = [str(f) for f in python_files[:100]]
            
            js_files = list(self.target_path.rglob("*.js")) + list(self.target_path.rglob("*.jsx"))
            if js_files:
                project_info['javascript'] = True
                project_info['js_files'] = [str(f) for f in js_files[:100]]
            
            package_jsons = list(self.target_path.rglob("package.json"))
            if package_jsons:
                project_info['nodejs'] = True
                project_info['package_json'] = [str(f.parent) for f in package_jsons]
        
        return project_info
    
    def run_scan(self, script_name, *args):
        """Run a scanner script and capture output"""
        script_path = Path(__file__).parent / script_name
        
        try:
            result = subprocess.run(
                [sys.executable, str(script_path), *args],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return {
                'success': result.returncode in [0, 1],  # 0 = clean, 1 = vulns found
                'output': result.stdout,
                'exit_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': 'Scan timeout after 5 minutes',
                'exit_code': 124
            }
        except Exception as e:
            return {
                'success': False,
                'output': f'Error running scanner: {str(e)}',
                'exit_code': 2
            }
    
    def aggregate_results(self):
        """Aggregate and categorize all vulnerabilities"""
        for vuln in self.results['all_vulnerabilities']:
            severity = vuln.get('severity', 'medium').lower()
            
            if severity in ['critical']:
                self.results['critical_vulnerabilities'].append(vuln)
                self.results['critical_count'] += 1
            elif severity in ['high']:
                self.results['high_vulnerabilities'].append(vuln)
                self.results['high_count'] += 1
            elif severity in ['medium', 'moderate']:
                self.results['medium_vulnerabilities'].append(vuln)
                self.results['medium_count'] += 1
            else:
                self.results['low_vulnerabilities'].append(vuln)
                self.results['low_count'] += 1
    
    def run_comprehensive_scan(self):
        """Run all enabled security scans"""
        print(f"\n🚀 Starting Enhanced Security Scan")
        print(f"{'='*70}")
        print(f"Target: {self.target_path}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        project_info = self.detect_project_type()
        
        # Python scanning
        if project_info['python'] and self.config['scan']['python']:
            print("🔍 Running Python security scan (Bandit)...")
            self.results['scans_performed'].append('Python (Bandit)')
            result = self.run_scan('scan_python.py', str(self.target_path))
            if result['success']:
                print(result['output'])
                self.results['files_scanned'] += len(project_info['python_files'])
        
        # JavaScript scanning
        if project_info['javascript'] and self.config['scan']['javascript']:
            print("\n🔍 Running JavaScript security scan (ESLint)...")
            self.results['scans_performed'].append('JavaScript (ESLint)')
            result = self.run_scan('scan_javascript.py', 'code', str(self.target_path))
            if result['success']:
                print(result['output'])
                self.results['files_scanned'] += len(project_info['js_files'])
        
        # Node.js dependency scanning
        if project_info['nodejs'] and self.config['scan']['dependencies']:
            print("\n🔍 Running Node.js dependency scan (npm audit)...")
            self.results['scans_performed'].append('Dependencies (npm audit)')
            for project_dir in project_info['package_json']:
                result = self.run_scan('scan_javascript.py', 'npm', project_dir)
                if result['success']:
                    print(result['output'])
                break  # Only first package.json
        
        # Secret scanning
        if self.config['scan']['secrets']:
            print("\n🔍 Running secret detection scan...")
            self.results['scans_performed'].append('Secrets Detection')
            result = self.run_scan('scan_secrets.py', str(self.target_path))
            if result['success']:
                print(result['output'])
                # Parse secrets count from output
                if 'Secrets Found:' in result['output']:
                    for line in result['output'].split('\n'):
                        if 'Secrets Found:' in line:
                            try:
                                count = int(line.split(':')[1].strip())
                                self.results['secrets_found'] = count
                            except:
                                pass
        
        # Aggregate results
        self.aggregate_results()
        
        # Calculate scan duration
        duration = time.time() - self.start_time
        self.results['scan_duration'] = f"{duration:.1f} seconds"
        
        return self.results
    
    def generate_reports(self):
        """Generate output reports in configured formats"""
        print(f"\n📊 Generating reports...")
        
        output_formats = self.config['output']['formats']
        
        # JSON report
        if 'json' in output_formats:
            json_path = self.config['output']['json_file']
            with open(json_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"✅ JSON report: {json_path}")
        
        # HTML report
        if 'html' in output_formats:
            try:
                from generate_html_report import generate_html_report
                html_path = generate_html_report(self.results, 
                                                self.config['output']['html_file'])
                print(f"✅ HTML report: {html_path}")
            except Exception as e:
                print(f"⚠️  Could not generate HTML report: {e}")
        
        # SARIF report
        if 'sarif' in output_formats:
            try:
                from generate_sarif import generate_sarif_report
                sarif_path = generate_sarif_report(self.results,
                                                   self.config['output']['sarif_file'])
                print(f"✅ SARIF report: {sarif_path}")
            except Exception as e:
                print(f"⚠️  Could not generate SARIF report: {e}")
    
    def print_summary(self):
        """Print executive summary"""
        print(f"\n{'='*70}")
        print("📊 SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Scans Completed: {len(self.results['scans_performed'])}")
        print(f"  • {', '.join(self.results['scans_performed'])}")
        print(f"\nFiles Scanned: {self.results['files_scanned']}")
        print(f"Scan Duration: {self.results['scan_duration']}")
        
        total_vulns = (self.results['critical_count'] + self.results['high_count'] + 
                      self.results['medium_count'] + self.results['low_count'])
        
        print(f"\nVulnerabilities Found: {total_vulns}")
        print(f"  🔴 Critical: {self.results['critical_count']}")
        print(f"  🟠 High:     {self.results['high_count']}")
        print(f"  🟡 Medium:   {self.results['medium_count']}")
        print(f"  🟢 Low:      {self.results['low_count']}")
        
        if self.results['secrets_found'] > 0:
            print(f"\n🔐 Secrets Detected: {self.results['secrets_found']}")
            print("   ⚠️  Rotate credentials immediately!")
        
        # Risk assessment
        risk_score = self.calculate_risk_score()
        risk_level, risk_emoji = self.get_risk_level(risk_score)
        
        print(f"\n{risk_emoji} Overall Risk Score: {risk_score}/100 ({risk_level})")
        
        print(f"{'='*70}\n")
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        weights = self.config.get('risk_scoring', {}).get('weights', {
            'critical': 25, 'high': 10, 'medium': 3, 'low': 1
        })
        
        score = (
            self.results['critical_count'] * weights.get('critical', 25) +
            self.results['high_count'] * weights.get('high', 10) +
            self.results['medium_count'] * weights.get('medium', 3) +
            self.results['low_count'] * weights.get('low', 1)
        )
        
        return min(score, 100)
    
    def get_risk_level(self, score):
        """Get risk level description"""
        if score >= 75:
            return "CRITICAL", "🔴"
        elif score >= 50:
            return "HIGH", "🟠"
        elif score >= 25:
            return "MEDIUM", "🟡"
        else:
            return "LOW", "🟢"
    
    def should_fail_build(self):
        """Determine if build should fail based on findings"""
        fail_on = self.config['severity']['fail_on'].lower()
        
        if fail_on == 'critical' and self.results['critical_count'] > 0:
            return True
        elif fail_on == 'high' and (self.results['critical_count'] > 0 or 
                                    self.results['high_count'] > 0):
            return True
        elif fail_on == 'medium' and (self.results['critical_count'] > 0 or 
                                      self.results['high_count'] > 0 or
                                      self.results['medium_count'] > 0):
            return True
        
        return False


def main():
    if len(sys.argv) < 2:
        print("Enhanced Application Security Scanner")
        print("\nUsage: python run_security_scan.py <path> [options]")
        print("\nOptions:")
        print("  --config <file>      Path to configuration file")
        print("  --skip-python        Skip Python security scan")
        print("  --skip-javascript    Skip JavaScript security scan")
        print("  --skip-secrets       Skip secret detection")
        print("  --skip-dependencies  Skip dependency scan")
        print("  --format <formats>   Output formats (text,json,html,sarif)")
        print("\nExamples:")
        print("  python run_security_scan.py .")
        print("  python run_security_scan.py /path/to/project --config .appsec-config.yml")
        print("  python run_security_scan.py . --skip-secrets --format html,json")
        sys.exit(1)
    
    target_path = sys.argv[1]
    
    # Parse command line options
    config_path = None
    skip_options = {}
    output_formats = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--config' and i + 1 < len(sys.argv):
            config_path = sys.argv[i + 1]
            i += 2
        elif arg == '--format' and i + 1 < len(sys.argv):
            # Parse comma-separated formats (e.g., "html,json")
            output_formats = [f.strip().lower() for f in sys.argv[i + 1].split(',')]
            i += 2
        elif arg == '--skip-python':
            skip_options['python'] = False
            i += 1
        elif arg == '--skip-javascript':
            skip_options['javascript'] = False
            i += 1
        elif arg == '--skip-secrets':
            skip_options['secrets'] = False
            i += 1
        elif arg == '--skip-dependencies':
            skip_options['dependencies'] = False
            i += 1
        else:
            i += 1

    # Create scanner
    scanner = SecurityScanner(target_path, config_path)

    # Apply command line skip options
    if skip_options:
        scanner.config['scan'].update(skip_options)

    # Apply command line format options
    if output_formats:
        scanner.config['output']['formats'] = output_formats
    
    # Run comprehensive scan
    results = scanner.run_comprehensive_scan()
    
    # Generate reports
    scanner.generate_reports()
    
    # Print summary
    scanner.print_summary()
    
    # Exit with appropriate code
    if scanner.should_fail_build():
        print("❌ Build failed due to security vulnerabilities")
        sys.exit(1)
    else:
        print("✅ Security scan completed")
        sys.exit(0)


if __name__ == "__main__":
    main()
