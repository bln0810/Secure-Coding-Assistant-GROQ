"""
Security Analyzer - Core vulnerability detection engine
Analyzes code for common security issues and OWASP Top 10 vulnerabilities
"""

import re
import ast
import json
from typing import List, Dict, Any, Tuple
import hashlib
import os

class Vulnerability:
    """Represents a security vulnerability found in code"""
    
    def __init__(self, vuln_type: str, severity: str, line: int, description: str, 
                 code_snippet: str = "", suggestion: str = "", owasp_category: str = ""):
        self.type = vuln_type
        self.severity = severity  # high, medium, low
        self.line = line
        self.description = description
        self.code_snippet = code_snippet
        self.suggestion = suggestion
        self.owasp_category = owasp_category
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format"""
        return {
            'type': self.type,
            'severity': self.severity,
            'line': self.line,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'suggestion': self.suggestion,
            'owasp_category': self.owasp_category
        }

class SecurityAnalyzer:
    """Main security analysis engine"""
    
    def __init__(self):
        self.python_patterns = self._load_python_patterns()
        self.javascript_patterns = self._load_javascript_patterns()
        
        # Initialize AI analyzer (Groq)
        self.ai_analyzer = None
        try:
            from .ai_analyzer import AIAnalyzer
            self.ai_analyzer = AIAnalyzer()
        except ImportError:
            pass
    
    def analyze(self, code: str, language: str) -> Dict[str, Any]:
        """
        Main analysis function
        
        Args:
            code: Source code to analyze
            language: Programming language ('python' or 'javascript')
        
        Returns:
            Dictionary containing analysis results
        """
        vulnerabilities = []
        
        try:
            if language == 'python':
                vulnerabilities = self._analyze_python(code)
            elif language == 'javascript':
                vulnerabilities = self._analyze_javascript(code)
            else:
                return {'error': f'Unsupported language: {language}'}
            
            # Enhance vulnerabilities with AI if available
            if self.ai_analyzer and self.ai_analyzer.enabled:
                try:
                    vulnerabilities = self.ai_analyzer.enhance_vulnerabilities(vulnerabilities, code, language)
                except Exception as e:
                    print(f"AI enhancement failed: {str(e)}")
            
            # Generate summary statistics
            summary = self._generate_summary(vulnerabilities)
            
            return {
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
                'summary': summary,
                'language': language,
                'total_lines': len(code.split('\n')),
                'ai_enhanced': bool(self.ai_analyzer and self.ai_analyzer.enabled)
            }
        
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def _analyze_python(self, code: str) -> List[Vulnerability]:
        """Analyze Python code for vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Static pattern matching
        for pattern_info in self.python_patterns:
            matches = self._find_pattern_matches(code, pattern_info, lines)
            vulnerabilities.extend(matches)
        
        # AST-based analysis for more complex patterns
        try:
            tree = ast.parse(code)
            ast_vulnerabilities = self._analyze_python_ast(tree, lines)
            vulnerabilities.extend(ast_vulnerabilities)
        except SyntaxError as e:
            # Add syntax error as a vulnerability
            vulnerabilities.append(Vulnerability(
                vuln_type="Syntax Error",
                severity="high",
                line=getattr(e, 'lineno', 1),
                description=f"Python syntax error: {str(e)}",
                suggestion="Fix the syntax error before proceeding with security analysis."
            ))
        
        return vulnerabilities
    
    def _analyze_javascript(self, code: str) -> List[Vulnerability]:
        """Analyze JavaScript code for vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Static pattern matching for JavaScript
        for pattern_info in self.javascript_patterns:
            matches = self._find_pattern_matches(code, pattern_info, lines)
            vulnerabilities.extend(matches)
        
        return vulnerabilities
    
    def _analyze_python_ast(self, tree: ast.AST, lines: List[str]) -> List[Vulnerability]:
        """Analyze Python AST for complex vulnerability patterns"""
        vulnerabilities = []
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    line_num = getattr(node, 'lineno', 1)
                    
                    if func_name == 'eval':
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Code Injection",
                            severity="high",
                            line=line_num,
                            description="Use of 'eval()' function can lead to code injection vulnerabilities.",
                            code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                            suggestion="Avoid using eval(). Use safer alternatives like ast.literal_eval() for evaluating literals.",
                            owasp_category="A03:2021 - Injection"
                        ))
                    
                    elif func_name == 'exec':
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Code Injection",
                            severity="high",
                            line=line_num,
                            description="Use of 'exec()' function can lead to code injection vulnerabilities.",
                            code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                            suggestion="Avoid using exec(). Consider safer alternatives or proper input validation.",
                            owasp_category="A03:2021 - Injection"
                        ))
            
            # Check for hardcoded strings that might be credentials
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                line_num = getattr(node, 'lineno', 1)
                value = node.value
                
                if self._is_potential_credential(value):
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Hardcoded Credential",
                        severity="high",
                        line=line_num,
                        description="Potential hardcoded credential or API key detected.",
                        code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                        suggestion="Store sensitive information in environment variables or secure configuration files.",
                        owasp_category="A07:2021 - Identification and Authentication Failures"
                    ))
        
        return vulnerabilities
    
    def _find_pattern_matches(self, code: str, pattern_info: Dict, lines: List[str]) -> List[Vulnerability]:
        """Find pattern matches in code"""
        vulnerabilities = []
        pattern = pattern_info['pattern']
        
        for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
            # Find line number
            line_num = code[:match.start()].count('\n') + 1
            
            vulnerabilities.append(Vulnerability(
                vuln_type=pattern_info['type'],
                severity=pattern_info['severity'],
                line=line_num,
                description=pattern_info['description'],
                code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                suggestion=pattern_info['suggestion'],
                owasp_category=pattern_info.get('owasp_category', '')
            ))
        
        return vulnerabilities
    
    def _is_potential_credential(self, value: str) -> bool:
        """Check if a string might be a credential"""
        if len(value) < 10:
            return False
        
        # Common patterns for API keys, tokens, etc.
        credential_patterns = [
            r'^sk-[a-zA-Z0-9]{20,}$',  # OpenAI API keys
            r'^[A-Za-z0-9]{32,}$',     # Generic long alphanumeric strings
            r'.*(?:password|passwd|pwd|secret|token|key|api).*',  # Contains credential keywords
        ]
        
        for pattern in credential_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {
            'total_issues': len(vulnerabilities),
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in summary:
                summary[vuln.severity] += 1
        
        return summary
    
    def _load_python_patterns(self) -> List[Dict]:
        """Load Python-specific vulnerability patterns"""
        return [
            # A01:2021 - Broken Access Control
            {
                'pattern': r'@app\.route.*?methods=\[.*?(?<!\'POST\').*?\]',
                'type': 'Broken Access Control',
                'severity': 'high',
                'description': 'Endpoint might be missing proper HTTP method restrictions.',
                'suggestion': 'Explicitly specify allowed HTTP methods and implement proper access controls.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            {
                'pattern': r'flask_login\.current_user',
                'type': 'Broken Access Control',
                'severity': 'medium',
                'description': 'Ensure proper access control checks are implemented when using current_user.',
                'suggestion': 'Implement role-based access control and validate user permissions.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            {
                'pattern': r'@cross_origin\(.*?\)|CORS\(app.*?\)',
                'type': 'CORS Misconfiguration',
                'severity': 'high',
                'description': 'Potentially insecure CORS configuration detected.',
                'suggestion': 'Restrict CORS to specific origins, methods, and headers. Avoid using wildcard (*) in production.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            {
                'pattern': r'@(?:requires_role|role_required|has_role)\s*\([\'"]admin[\'"]\)',
                'type': 'Role-Based Access Control',
                'severity': 'medium',
                'description': 'Hardcoded role check detected. Ensure comprehensive role validation.',
                'suggestion': 'Implement granular role-based access control with proper role hierarchy.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            {
                'pattern': r'session\[.*?\].*?=|request\.cookies\[.*?\].*?=',
                'type': 'Session Management',
                'severity': 'high',
                'description': 'Direct session/cookie manipulation detected.',
                'suggestion': 'Use secure session management with proper validation and encryption.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            # A02:2021 - Cryptographic Failures
            {
                'pattern': r'request\.cookies\.get\(.*?\)',
                'type': 'Cryptographic Failure',
                'severity': 'medium',
                'description': 'Accessing cookies without secure flag verification.',
                'suggestion': 'Use secure cookies and implement proper cookie security flags.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            {
                'pattern': r'SSLContext\(.*?PROTOCOL_TLSv1.*?\)|ssl\.PROTOCOL_TLSv1',
                'type': 'Weak TLS Configuration',
                'severity': 'high',
                'description': 'Usage of outdated TLS protocol version detected.',
                'suggestion': 'Use TLS 1.3 or at minimum TLS 1.2. Avoid older versions.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            {
                'pattern': r'Crypto\.Cipher\.(?:DES|Blowfish|RC4)|cryptography\.hazmat\.primitives\.ciphers\.algorithms\.(?:DES|Blowfish)',
                'type': 'Weak Cipher',
                'severity': 'high',
                'description': 'Usage of weak or outdated cipher algorithms detected.',
                'suggestion': 'Use strong encryption algorithms like AES-256-GCM with proper key management.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            {
                'pattern': r'(?:SECRET|PRIVATE)_KEY\s*=\s*[\'"][^\'"]+[\'"]|private_key\s*=\s*[\'"][^\'"]+[\'"]',
                'type': 'Key Management',
                'severity': 'high',
                'description': 'Hardcoded cryptographic key detected.',
                'suggestion': 'Use secure key management systems and environment variables for sensitive keys.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            # A03:2021 - Injection
            {
                'pattern': r'cursor\.execute\s*\(\s*["\'].*?\+.*?["\']',
                'type': 'SQL Injection',
                'severity': 'high',
                'description': 'Potential SQL injection vulnerability detected. String concatenation in SQL queries can allow attackers to inject malicious SQL code.',
                'suggestion': 'Use parameterized queries or prepared statements instead of string concatenation.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'cursor\.execute\s*\(\s*f["\'].*?\{.*?\}',
                'type': 'SQL Injection',
                'severity': 'high',
                'description': 'Potential SQL injection vulnerability detected. F-string formatting in SQL queries can allow SQL injection attacks.',
                'suggestion': 'Use parameterized queries with ? placeholders instead of f-strings.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'\.execute\s*\(\s*["\'].*?%.*?["\'].*?%',
                'type': 'SQL Injection',
                'severity': 'high',
                'description': 'Potential SQL injection vulnerability detected. String formatting in SQL queries is dangerous.',
                'suggestion': 'Use parameterized queries instead of string formatting.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'pickle\.loads?\s*\(',
                'type': 'Deserialization Attack',
                'severity': 'high',
                'description': 'Pickle deserialization can execute arbitrary code and should not be used with untrusted data.',
                'suggestion': 'Use safer serialization formats like JSON, or validate/sanitize pickle data sources.',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures'
            },
            {
                'pattern': r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
                'type': 'Command Injection',
                'severity': 'high',
                'description': 'Using shell=True in subprocess calls can lead to command injection vulnerabilities.',
                'suggestion': 'Use shell=False and pass arguments as a list, or properly validate/sanitize input.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'os\.system\s*\(',
                'type': 'Command Injection',
                'severity': 'high',
                'description': 'Using os.system() with user input can lead to command injection vulnerabilities.',
                'suggestion': 'Use subprocess module with proper argument validation instead of os.system().',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'(?:query|sql)\s*=\s*["\'].*?\+|["\'].*?SELECT.*?\+|["\'].*?INSERT.*?\+|["\'].*?UPDATE.*?\+|["\'].*?DELETE.*?\+',
                'type': 'SQL Injection',
                'severity': 'high',
                'description': 'String concatenation in SQL query construction can lead to SQL injection.',
                'suggestion': 'Use parameterized queries or ORM methods instead of string concatenation.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'open\s*\(\s*[^,)]+\s*[,)]',
                'type': 'Path Traversal',
                'severity': 'medium',
                'description': 'Unrestricted file path handling can lead to path traversal vulnerabilities.',
                'suggestion': 'Validate and sanitize file paths. Use os.path.abspath() and check if the path is within allowed directories.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            {
                'pattern': r'f["\']<.*?\{.*?\}.*?["\']|["\']<.*?["\'].*?\+.*?["\'].*?>',
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'description': 'Generating HTML with user input can lead to XSS vulnerabilities.',
                'suggestion': 'Use template engines with auto-escaping or explicitly escape user input before including in HTML.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
                'type': 'Hardcoded Credential',
                'severity': 'high',
                'description': 'Hardcoded password detected in source code.',
                'suggestion': 'Store credentials in environment variables or secure configuration management systems.',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures'
            },
            {
                'pattern': r'random\.random\(\)|random\.randint\(',
                'type': 'Weak Random Number Generator',
                'severity': 'medium',
                'description': 'The random module is not cryptographically secure and should not be used for security-sensitive operations.',
                'suggestion': 'Use secrets module for cryptographically strong random numbers.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            {
                'pattern': r'\bmd5\s*\(|hashlib\.md5\s*\(',
                'type': 'Weak Cryptographic Hash',
                'severity': 'medium',
                'description': 'MD5 is cryptographically broken and should not be used for security purposes.',
                'suggestion': 'Use SHA-256 or other secure hash functions from hashlib.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            # A04:2021 - Insecure Design
            {
                'pattern': r'except\s*:|\bexcept\s*Exception\s*:',
                'type': 'Insecure Design',
                'severity': 'medium',
                'description': 'Overly broad exception handling can mask security issues.',
                'suggestion': 'Catch specific exceptions and handle errors appropriately.',
                'owasp_category': 'A04:2021 - Insecure Design'
            },
            # A05:2021 - Security Misconfiguration
            {
                'pattern': r'DEBUG\s*=\s*True',
                'type': 'Security Misconfiguration',
                'severity': 'high',
                'description': 'Debug mode enabled in production environment.',
                'suggestion': 'Disable debug mode in production settings.',
                'owasp_category': 'A05:2021 - Security Misconfiguration'
            },
            {
                'pattern': r'ALLOWED_HOSTS\s*=\s*\[\s*[\'\"]\*[\'\"]',
                'type': 'Security Misconfiguration',
                'severity': 'high',
                'description': 'Wildcard in ALLOWED_HOSTS is insecure.',
                'suggestion': 'Explicitly list allowed host/domain names.',
                'owasp_category': 'A05:2021 - Security Misconfiguration'
            },
            {
                'pattern': r'ssl\._create_unverified_context',
                'type': 'Disabled SSL Verification',
                'severity': 'high',
                'description': 'Disabling SSL certificate verification makes the application vulnerable to man-in-the-middle attacks.',
                'suggestion': 'Always verify SSL certificates in production. Use proper certificate validation.',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures'
            },
            # A08:2021 - Software and Data Integrity Failures
            {
                'pattern': r'yaml\.load\((?!.*Loader=yaml\.SafeLoader)',
                'type': 'Software and Data Integrity Failure',
                'severity': 'high',
                'description': 'Unsafe YAML loading can lead to code execution.',
                'suggestion': 'Use yaml.safe_load() or specify SafeLoader explicitly.',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures'
            },
            # A09:2021 - Security Logging and Monitoring Failures
            {
                'pattern': r'(?<!logging\.)\b(print|sys\.stdout\.write)\(',
                'type': 'Logging Failure',
                'severity': 'medium',
                'description': 'Using print statements instead of proper logging.',
                'suggestion': 'Use the logging module for proper audit trails.',
                'owasp_category': 'A09:2021 - Security Logging and Monitoring Failures'
            },
            # A10:2021 - Server-Side Request Forgery (SSRF)
            {
                'pattern': r'requests\.(?:get|post|put|delete)\s*\(\s*(?:[^,]+,\s*)*(?:verify\s*=\s*False|allow_redirects\s*=\s*True)',
                'type': 'SSRF',
                'severity': 'high',
                'description': 'Potential SSRF vulnerability in HTTP request.',
                'suggestion': 'Validate URLs, use allowlists, and keep SSL verification enabled.',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery'
            },
            {
                'pattern': r'urllib\.(?:request\.urlopen|parse\.urljoin)\(',
                'type': 'SSRF',
                'severity': 'medium',
                'description': 'Potential SSRF vulnerability with URL handling.',
                'suggestion': 'Validate URLs and implement proper URL allowlisting.',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery'
            }
        ]
    
    def _load_javascript_patterns(self) -> List[Dict]:
        """Load JavaScript-specific vulnerability patterns"""
        return [
            # A01:2021 - Broken Access Control
            {
                'pattern': r'location\.href\s*=|window\.location\s*=',
                'type': 'Broken Access Control',
                'severity': 'high',
                'description': 'Unvalidated client-side redirects can lead to access control bypasses.',
                'suggestion': 'Validate and sanitize URLs before redirecting.',
                'owasp_category': 'A01:2021 - Broken Access Control'
            },
            # A02:2021 - Cryptographic Failures
            {
                'pattern': r'localStorage\.|sessionStorage\.',
                'type': 'Cryptographic Failure',
                'severity': 'medium',
                'description': 'Storing sensitive data in browser storage without encryption.',
                'suggestion': 'Use secure storage methods and encrypt sensitive data.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            # A03:2021 - Injection
            {
                'pattern': r'\.innerHTML\s*[\+\=].*?\+',
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'description': 'Direct assignment to innerHTML with user input can lead to XSS vulnerabilities.',
                'suggestion': 'Use textContent instead of innerHTML, or properly sanitize HTML content.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'document\.write\s*\(',
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'description': 'Using document.write() with user input can lead to XSS vulnerabilities.',
                'suggestion': 'Use safer DOM manipulation methods like createElement() and textContent.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'eval\s*\(',
                'type': 'Code Injection',
                'severity': 'high',
                'description': 'Using eval() can execute arbitrary JavaScript code and is dangerous with user input.',
                'suggestion': 'Avoid eval(). Use JSON.parse() for JSON data or other safer alternatives.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'Function\s*\(',
                'type': 'Code Injection',
                'severity': 'high',
                'description': 'The Function constructor can execute arbitrary code, similar to eval().',
                'suggestion': 'Avoid the Function constructor. Use safer alternatives.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'setTimeout\s*\(\s*["\'].*?["\']',
                'type': 'Code Injection',
                'severity': 'medium',
                'description': 'Using setTimeout/setInterval with string arguments can execute arbitrary code.',
                'suggestion': 'Pass a function reference instead of a string to setTimeout/setInterval.',
                'owasp_category': 'A03:2021 - Injection'
            },
            {
                'pattern': r'(api_key|apikey|secret|password|token)\s*[:=]\s*["\'][^"\']{10,}["\']',
                'type': 'Hardcoded Credential',
                'severity': 'high',
                'description': 'Hardcoded API keys, passwords, or secrets detected in the code.',
                'suggestion': 'Store sensitive information in environment variables or secure configuration.',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures'
            },
            {
                'pattern': r'localStorage\.setItem.*?(password|token|secret|key)',
                'type': 'Insecure Storage',
                'severity': 'medium',
                'description': 'Storing sensitive information in localStorage is insecure.',
                'suggestion': 'Use secure storage mechanisms and avoid storing sensitive data in browser storage.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            {
                'pattern': r'Math\.random\(\)',
                'type': 'Weak Random Number Generator',
                'severity': 'medium',
                'description': 'Math.random() is not cryptographically secure.',
                'suggestion': 'Use crypto.getRandomValues() for cryptographically secure random numbers.',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            # A04:2021 - Insecure Design
            {
                'pattern': r'try\s*{\s*.*?\s*}\s*catch\s*\(\s*(?:error|err|e)?\s*\)',
                'type': 'Insecure Design',
                'severity': 'medium',
                'description': 'Generic error handling can expose sensitive information.',
                'suggestion': 'Implement proper error handling and logging.',
                'owasp_category': 'A04:2021 - Insecure Design'
            },
            # A05:2021 - Security Misconfiguration
            {
                'pattern': r'console\.(log|debug|info)',
                'type': 'Security Misconfiguration',
                'severity': 'low',
                'description': 'Debug logging in production code can expose sensitive information.',
                'suggestion': 'Remove or disable debug logging in production.',
                'owasp_category': 'A05:2021 - Security Misconfiguration'
            },
            # A06:2021 - Vulnerable Components
            {
                'pattern': r'require\([\'"](?!\.)[^\'"]+[\'"]\)',
                'type': 'Vulnerable Components',
                'severity': 'medium',
                'description': 'External package import without version pinning.',
                'suggestion': 'Pin package versions and regularly update dependencies.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            },
            {
                'pattern': r'pip\s+install\s+[-\w]+(?!\s*==)',
                'type': 'Python Package Version',
                'severity': 'medium',
                'description': 'Python package installation without version pinning.',
                'suggestion': 'Use exact version pins (==) in requirements.txt and setup.py.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            },
            {
                'pattern': r'yarn\s+add\s+[-\w]+(?!\s*@)|npm\s+install\s+[-\w]+(?!\s*@)',
                'type': 'Node Package Version',
                'severity': 'medium',
                'description': 'Node.js package installation without version pinning.',
                'suggestion': 'Use exact versions in package.json and consider using package-lock.json.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            },
            {
                'pattern': r'requirements\.txt|setup\.py',
                'type': 'Dependency Management',
                'severity': 'low',
                'description': 'Check dependency management files for outdated packages.',
                'suggestion': 'Regularly update dependencies and use tools like safety, npm audit, or Dependabot.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            },
            {
                'pattern': r'(?:from|import)\s+(?:django|flask|requests|numpy|tensorflow)(?!\s+as)',
                'type': 'Common Package Usage',
                'severity': 'low',
                'description': 'Usage of common packages detected. Ensure up-to-date versions.',
                'suggestion': 'Regularly check for security updates in commonly used packages.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            },
            # A07:2021 - Authentication Failures
            {
                'pattern': r'password|token|secret|key\s*[=:]\s*["\'][^"\']+["\']',
                'type': 'Authentication Failure',
                'severity': 'high',
                'description': 'Hardcoded credentials detected.',
                'suggestion': 'Use environment variables or secure credential storage.',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures'
            },
            # A08:2021 - Software and Data Integrity
            {
                'pattern': r'JSON\.parse\(\s*[^,\)]+\)',
                'type': 'Software and Data Integrity',
                'severity': 'medium',
                'description': 'Parsing JSON without validation can lead to prototype pollution.',
                'suggestion': 'Validate JSON data before parsing.',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures'
            },
            # A09:2021 - Logging Failures
            {
                'pattern': r'catch\s*\([^)]*\)\s*{\s*}',
                'type': 'Logging Failure',
                'severity': 'medium',
                'description': 'Empty catch block suppresses errors without logging.',
                'suggestion': 'Implement proper error logging in catch blocks.',
                'owasp_category': 'A09:2021 - Security Logging and Monitoring Failures'
            },
            # A10:2021 - SSRF
            {
                'pattern': r'fetch\s*\(\s*(?:[^,]+,\s*)*\)',
                'type': 'SSRF',
                'severity': 'medium',
                'description': 'Potential SSRF vulnerability in fetch request.',
                'suggestion': 'Validate URLs and implement proper URL allowlisting.',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery'
            }
        ]