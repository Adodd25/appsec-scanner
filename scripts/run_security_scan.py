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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple, Callable


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
                'dependencies': True,
                'semgrep': True  # Advanced SAST with data flow analysis
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
        import fnmatch

        project_info = {
            'python': False,
            'javascript': False,
            'typescript': False,
            'nodejs': False,
            'python_files': [],
            'js_files': [],
            'ts_files': [],
            'package_json': []
        }

        # Get exclude patterns from config (glob patterns like "**/node_modules/**")
        exclude_patterns = self.config.get('scan', {}).get('exclude', [])

        # Default directories to always exclude
        default_exclude_dirs = {'node_modules', '.git', '__pycache__', 'venv', 'env',
                                '.venv', 'dist', 'build', '.pytest_cache', '.mypy_cache',
                                'coverage', 'htmlcov', '.tox', 'site-packages'}

        def should_include(path: Path) -> bool:
            """Check if path should be included based on exclude patterns"""
            path_str = str(path)

            # Check default directory exclusions
            for part in path.parts:
                if part in default_exclude_dirs:
                    return False

            # Check config glob patterns
            for pattern in exclude_patterns:
                # Convert glob pattern to work with fnmatch
                # Handle patterns like "**/node_modules/**"
                clean_pattern = pattern.strip()
                if fnmatch.fnmatch(path_str, clean_pattern):
                    return False
                # Also check against relative path
                try:
                    rel_path = str(path.relative_to(self.target_path))
                    if fnmatch.fnmatch(rel_path, clean_pattern):
                        return False
                except ValueError:
                    pass

            return True

        # Search for files
        if self.target_path.is_file():
            if self.target_path.suffix == ".py":
                project_info['python'] = True
                project_info['python_files'].append(str(self.target_path))
            elif self.target_path.suffix in [".js", ".jsx"]:
                project_info['javascript'] = True
                project_info['js_files'].append(str(self.target_path))
            elif self.target_path.suffix in [".ts", ".tsx"]:
                project_info['typescript'] = True
                project_info['javascript'] = True  # TS is scanned with JS scanner
                project_info['ts_files'].append(str(self.target_path))
        else:
            # Scan directory - no arbitrary limits
            python_files = [f for f in self.target_path.rglob("*.py") if should_include(f)]
            if python_files:
                project_info['python'] = True
                project_info['python_files'] = [str(f) for f in python_files]

            js_files = [f for f in self.target_path.rglob("*.js") if should_include(f)]
            jsx_files = [f for f in self.target_path.rglob("*.jsx") if should_include(f)]
            all_js = js_files + jsx_files
            if all_js:
                project_info['javascript'] = True
                project_info['js_files'] = [str(f) for f in all_js]

            ts_files = [f for f in self.target_path.rglob("*.ts") if should_include(f)]
            tsx_files = [f for f in self.target_path.rglob("*.tsx") if should_include(f)]
            all_ts = ts_files + tsx_files
            if all_ts:
                project_info['typescript'] = True
                project_info['javascript'] = True  # TS scanned with JS scanner
                project_info['ts_files'] = [str(f) for f in all_ts]

            package_jsons = [f for f in self.target_path.rglob("package.json") if should_include(f)]
            if package_jsons:
                project_info['nodejs'] = True
                project_info['package_json'] = [str(f.parent) for f in package_jsons]

        return project_info
    
    def run_scan(self, script_name, *args):
        """Run a scanner script and capture structured JSON output"""
        script_path = Path(__file__).parent / script_name

        try:
            result = subprocess.run(
                [sys.executable, str(script_path), '--json', *args],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Parse JSON output from scanner
            try:
                scan_result = json.loads(result.stdout) if result.stdout.strip() else {}
            except json.JSONDecodeError:
                # Fallback: scanner didn't output JSON
                scan_result = {'raw_output': result.stdout}

            return {
                'success': result.returncode in [0, 1],  # 0 = clean, 1 = vulns found
                'data': scan_result,
                'exit_code': result.returncode,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'data': {'error': 'Scan timeout after 5 minutes'},
                'exit_code': 124,
                'stderr': ''
            }
        except Exception as e:
            return {
                'success': False,
                'data': {'error': f'Error running scanner: {str(e)}'},
                'exit_code': 2,
                'stderr': ''
            }

    def normalize_severity(self, severity: str) -> str:
        """Normalize severity names across different tools"""
        severity = severity.lower().strip()
        # Map variations to standard names
        severity_map = {
            'moderate': 'medium',
            'warning': 'medium',
            'warn': 'medium',
            'error': 'high',
            'info': 'low',
            'informational': 'low'
        }
        return severity_map.get(severity, severity)

    def add_vulnerabilities(self, vulns: List[Dict], tool: str):
        """Add vulnerabilities from a scanner to the aggregated results"""
        for vuln in vulns:
            # Handle different severity field names from different tools
            # Bandit uses 'issue_severity', ESLint uses 'severity'
            severity = vuln.get('severity') or vuln.get('issue_severity') or 'medium'

            normalized = {
                'tool': tool,
                'severity': self.normalize_severity(severity),
                'title': vuln.get('title', vuln.get('test_name', vuln.get('ruleId', 'Security Issue'))),
                'description': vuln.get('description', vuln.get('issue_text', vuln.get('message', ''))),
                'file': vuln.get('file', vuln.get('filename', 'unknown')),
                'line': vuln.get('line', vuln.get('line_number', 0)),
                'column': vuln.get('column', vuln.get('col_offset', 1)),
                'code': vuln.get('code', vuln.get('line_content', '')),
                'fix': vuln.get('fix', vuln.get('more_info', '')),
                'rule_id': vuln.get('rule_id', vuln.get('test_id', vuln.get('ruleId', '')))
            }
            self.results['all_vulnerabilities'].append(normalized)
    
    def _vulnerability_fingerprint(self, vuln: Dict) -> str:
        """Create a unique fingerprint for a vulnerability to detect duplicates"""
        # Fingerprint based on file, line, tool, and rule/title
        return f"{vuln.get('file', '')}:{vuln.get('line', 0)}:{vuln.get('tool', '')}:{vuln.get('rule_id', vuln.get('title', ''))}"

    def deduplicate_vulnerabilities(self):
        """Remove duplicate vulnerabilities based on fingerprinting"""
        seen = set()
        unique_vulns = []

        for vuln in self.results['all_vulnerabilities']:
            fingerprint = self._vulnerability_fingerprint(vuln)
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique_vulns.append(vuln)

        self.results['all_vulnerabilities'] = unique_vulns

    def aggregate_results(self):
        """Aggregate and categorize all vulnerabilities"""
        # First deduplicate
        self.deduplicate_vulnerabilities()

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
    
    def _run_python_scan(self, project_info: Dict) -> Tuple[str, Dict]:
        """Run Python security scan - designed for parallel execution"""
        result = self.run_scan('scan_python.py', 'code', str(self.target_path))
        return ('python', {
            'result': result,
            'file_count': len(project_info['python_files']),
            'scan_name': 'Python (Bandit)'
        })

    def _run_pip_audit(self) -> Tuple[str, Dict]:
        """Run pip-audit for Python dependency scanning - designed for parallel execution"""
        result = self.run_scan('scan_python.py', 'deps', str(self.target_path))
        return ('pip_audit', {
            'result': result,
            'scan_name': 'Python Dependencies (pip-audit)'
        })

    def _run_js_scan(self, project_info: Dict) -> Tuple[str, Dict]:
        """Run JavaScript/TypeScript security scan - designed for parallel execution"""
        result = self.run_scan('scan_javascript.py', 'code', str(self.target_path))
        scan_name = 'JavaScript/TypeScript (ESLint)' if project_info['typescript'] else 'JavaScript (ESLint)'
        js_count = len(project_info['js_files']) + len(project_info.get('ts_files', []))
        return ('javascript', {
            'result': result,
            'file_count': js_count,
            'scan_name': scan_name
        })

    def _run_npm_scan(self, project_dir: str) -> Tuple[str, Dict]:
        """Run npm audit for a single project - designed for parallel execution"""
        result = self.run_scan('scan_javascript.py', 'npm', project_dir)
        return ('npm', {
            'result': result,
            'project_dir': project_dir
        })

    def _run_secrets_scan(self) -> Tuple[str, Dict]:
        """Run secret detection scan - designed for parallel execution"""
        result = self.run_scan('scan_secrets.py', str(self.target_path))
        return ('secrets', {'result': result})

    def _run_semgrep_scan(self) -> Tuple[str, Dict]:
        """Run Semgrep SAST scan - designed for parallel execution"""
        result = self.run_scan('scan_semgrep.py', str(self.target_path))
        return ('semgrep', {'result': result})

    def run_comprehensive_scan(self):
        """Run all enabled security scans in parallel where possible"""
        print(f"\n🚀 Starting Enhanced Security Scan")
        print(f"{'='*70}")
        print(f"Target: {self.target_path}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")

        project_info = self.detect_project_type()
        verbose = self.config['output'].get('verbose', False)

        # Prepare scan tasks for parallel execution
        scan_tasks = []

        if project_info['python'] and self.config['scan'].get('python', True):
            scan_tasks.append(('python', lambda: self._run_python_scan(project_info)))

        # Python dependency scanning with pip-audit
        if project_info['python'] and self.config['scan'].get('dependencies', True):
            scan_tasks.append(('pip_audit', lambda: self._run_pip_audit()))

        if project_info['javascript'] and self.config['scan'].get('javascript', True):
            scan_tasks.append(('javascript', lambda: self._run_js_scan(project_info)))

        if self.config['scan'].get('secrets', True):
            scan_tasks.append(('secrets', lambda: self._run_secrets_scan()))

        # Semgrep SAST scan (provides data flow analysis and taint tracking)
        if self.config['scan'].get('semgrep', True):
            scan_tasks.append(('semgrep', lambda: self._run_semgrep_scan()))

        # npm scans for each package.json (these can also run in parallel)
        if project_info['nodejs'] and self.config['scan'].get('dependencies', True):
            for project_dir in project_info['package_json']:
                # Capture project_dir in closure
                scan_tasks.append(('npm', lambda pd=project_dir: self._run_npm_scan(pd)))

        # Run scans in parallel
        print(f"🔄 Running {len(scan_tasks)} scan(s) in parallel...\n")

        with ThreadPoolExecutor(max_workers=min(4, len(scan_tasks) or 1)) as executor:
            futures = {executor.submit(task[1]): task[0] for task in scan_tasks}

            for future in as_completed(futures):
                scan_type, data = future.result()

                if scan_type == 'python':
                    result = data['result']
                    self.results['scans_performed'].append(data['scan_name'])
                    if result['success']:
                        vulns = result['data'].get('vulnerabilities', [])
                        self.add_vulnerabilities(vulns, 'Bandit')
                        self.results['files_scanned'] += result['data'].get('files_scanned', data['file_count'])
                        print(f"✅ Python (Bandit): Found {len(vulns)} issues")
                        if verbose and result.get('stderr'):
                            print(f"   {result['stderr']}")
                    else:
                        print(f"⚠️  Python scan failed: {result['data'].get('error', 'Unknown error')}")

                elif scan_type == 'javascript':
                    result = data['result']
                    self.results['scans_performed'].append(data['scan_name'])
                    if result['success']:
                        vulns = result['data'].get('vulnerabilities', [])
                        self.add_vulnerabilities(vulns, 'ESLint')
                        self.results['files_scanned'] += data['file_count']
                        print(f"✅ {data['scan_name']}: Found {len(vulns)} issues in {data['file_count']} files")
                    else:
                        print(f"⚠️  JavaScript scan failed: {result['data'].get('error', 'Unknown error')}")

                elif scan_type == 'pip_audit':
                    result = data['result']
                    self.results['scans_performed'].append(data['scan_name'])
                    if result['success']:
                        vulns = result['data'].get('vulnerabilities', [])
                        for vuln in vulns:
                            fix_versions = vuln.get('fix_versions', [])
                            fix_str = f"Upgrade to: {', '.join(fix_versions)}" if fix_versions else "No fix available"
                            self.results['all_vulnerabilities'].append({
                                'tool': 'pip-audit',
                                'severity': self.normalize_severity(vuln.get('severity', 'medium')),
                                'title': f"Vulnerable package: {vuln.get('package', 'unknown')}",
                                'description': f"{vuln.get('vulnerability_id', '')}: {vuln.get('description', '')}",
                                'file': vuln.get('source_file', 'requirements.txt'),
                                'line': 0,
                                'code': f"{vuln.get('package')}=={vuln.get('installed_version')}",
                                'fix': fix_str,
                                'rule_id': vuln.get('vulnerability_id', '')
                            })
                        self.results['outdated_dependencies'] += len(vulns)
                        print(f"✅ pip-audit: Found {len(vulns)} vulnerable packages")
                    else:
                        error = result['data'].get('error', 'Unknown error')
                        if 'not installed' in error:
                            print(f"⚠️  pip-audit not installed (skipping Python dependency scan)")
                        else:
                            print(f"⚠️  pip-audit failed: {error}")

                elif scan_type == 'npm':
                    result = data['result']
                    if 'Dependencies (npm audit)' not in self.results['scans_performed']:
                        self.results['scans_performed'].append('Dependencies (npm audit)')
                    if result['success']:
                        vulns = result['data'].get('vulnerabilities', [])
                        for vuln in vulns:
                            self.results['all_vulnerabilities'].append({
                                'tool': 'npm audit',
                                'severity': self.normalize_severity(vuln.get('severity', 'medium')),
                                'title': f"Vulnerable package: {vuln.get('package', 'unknown')}",
                                'description': f"Version range: {vuln.get('range', 'unknown')}",
                                'file': 'package.json',
                                'line': 0,
                                'code': '',
                                'fix': 'Fix available' if vuln.get('fixAvailable') else 'No fix available'
                            })
                        self.results['outdated_dependencies'] += len(vulns)
                        print(f"✅ npm audit ({data['project_dir']}): Found {len(vulns)} vulnerable packages")

                elif scan_type == 'secrets':
                    result = data['result']
                    self.results['scans_performed'].append('Secrets Detection')
                    if result['success']:
                        secrets = result['data'].get('secrets', [])
                        for secret in secrets:
                            self.results['all_vulnerabilities'].append({
                                'tool': 'Secret Scanner',
                                'severity': self.normalize_severity(secret.get('severity', 'high')),
                                'title': f"Exposed secret: {secret.get('type', 'Unknown')}",
                                'description': secret.get('description', 'Hardcoded secret detected'),
                                'file': secret.get('file', 'unknown'),
                                'line': secret.get('line', 0),
                                'code': '[REDACTED]',
                                'fix': 'Remove from code and use environment variables or secret manager'
                            })
                        self.results['secrets_found'] = len(secrets)
                        print(f"✅ Secret Scanner: Found {len(secrets)} potential secrets")
                    else:
                        print(f"⚠️  Secret scan failed: {result['data'].get('error', 'Unknown error')}")

                elif scan_type == 'semgrep':
                    result = data['result']
                    self.results['scans_performed'].append('Semgrep SAST')
                    if result['success']:
                        vulns = result['data'].get('vulnerabilities', [])
                        for vuln in vulns:
                            # Build rich description with CWE/OWASP info
                            desc = vuln.get('description', vuln.get('message', ''))
                            cwe = vuln.get('cwe', [])
                            owasp = vuln.get('owasp', [])

                            if cwe:
                                cwe_str = ', '.join(str(c) for c in cwe) if isinstance(cwe, list) else str(cwe)
                                desc = f"{desc} (CWE: {cwe_str})"
                            if owasp:
                                owasp_str = ', '.join(str(o) for o in owasp) if isinstance(owasp, list) else str(owasp)
                                desc = f"{desc} [OWASP: {owasp_str}]"

                            # Include taint analysis info if available
                            if vuln.get('is_taint_finding'):
                                taint_info = "[TAINT ANALYSIS] "
                                if vuln.get('taint_source'):
                                    src = vuln['taint_source']
                                    taint_info += f"Source: {src.get('file', '')}:{src.get('line', 0)} -> "
                                if vuln.get('taint_sink'):
                                    sink = vuln['taint_sink']
                                    taint_info += f"Sink: {sink.get('file', '')}:{sink.get('line', 0)}"
                                desc = f"{taint_info} {desc}"

                            self.results['all_vulnerabilities'].append({
                                'tool': 'Semgrep',
                                'severity': self.normalize_severity(vuln.get('severity', 'medium')),
                                'title': vuln.get('title', vuln.get('rule_id', 'Security Issue')),
                                'description': desc,
                                'file': vuln.get('file', 'unknown'),
                                'line': vuln.get('line', 0),
                                'column': vuln.get('column', 1),
                                'code': vuln.get('code', ''),
                                'fix': vuln.get('fix', ''),
                                'rule_id': vuln.get('rule_id', ''),
                                'cwe': cwe,
                                'owasp': owasp,
                                'references': vuln.get('references', [])
                            })

                        taint_count = sum(1 for v in vulns if v.get('is_taint_finding'))
                        taint_msg = f" ({taint_count} taint findings)" if taint_count > 0 else ""
                        self.results['files_scanned'] += result['data'].get('files_scanned', 0)
                        print(f"✅ Semgrep SAST: Found {len(vulns)} issues{taint_msg}")
                    else:
                        error = result['data'].get('error', 'Unknown error')
                        if 'not installed' in error:
                            print(f"⚠️  Semgrep not installed (skipping SAST scan)")
                        else:
                            print(f"⚠️  Semgrep scan failed: {error}")

        # Aggregate results by severity
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
        """
        Calculate overall risk score (0-100).

        Uses logarithmic scaling to provide meaningful differentiation:
        - 4 critical vulns shouldn't look the same as 400
        - Score approaches but never exceeds 100
        - Critical issues have outsized impact
        """
        import math

        critical = self.results['critical_count']
        high = self.results['high_count']
        medium = self.results['medium_count']
        low = self.results['low_count']

        # If any critical, minimum score is 50
        # Each additional critical adds diminishing points (log scale)
        if critical > 0:
            critical_score = 50 + min(30, 10 * math.log2(critical + 1))
        else:
            critical_score = 0

        # High issues: up to 40 points with log scaling
        if high > 0:
            high_score = min(40, 15 * math.log2(high + 1))
        else:
            high_score = 0

        # Medium issues: up to 20 points
        if medium > 0:
            medium_score = min(20, 7 * math.log2(medium + 1))
        else:
            medium_score = 0

        # Low issues: up to 10 points
        if low > 0:
            low_score = min(10, 3 * math.log2(low + 1))
        else:
            low_score = 0

        # Combine scores, cap at 100
        raw_score = critical_score + high_score + medium_score + low_score

        # Store raw score for reports (shows true magnitude)
        self.results['raw_risk_score'] = int(raw_score)

        return min(int(raw_score), 100)
    
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
        print("  --skip-semgrep       Skip Semgrep SAST scan")
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
        elif arg == '--skip-semgrep':
            skip_options['semgrep'] = False
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
