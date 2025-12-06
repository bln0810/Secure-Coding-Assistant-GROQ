"""
AI-Enhanced Security Analysis
Integrates with free AI APIs to provide enhanced vulnerability explanations and suggestions
"""

import requests
import json
import time
import os
from typing import List, Dict, Any, Optional
from .security_analyzer import Vulnerability

class AIAnalyzer:
    """AI-powered code analysis using free APIs"""
    
    def __init__(self, api_token: str = None, api_url: str = None):
        # Check for Groq API key
        self.groq_key = os.environ.get('GROQ_API_KEY')
        self.enabled = bool(self.groq_key)
    
    def enhance_vulnerabilities(self, vulnerabilities: List[Vulnerability], code: str, language: str) -> List[Vulnerability]:
        """
        Enhance vulnerability descriptions and suggestions using AI
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            code: Original code being analyzed
            language: Programming language
            
        Returns:
            Enhanced vulnerabilities with AI-generated insights
        """
        if not self.enabled or not vulnerabilities:
            return vulnerabilities
        
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                # Create enhanced vulnerability with AI insights
                enhanced_vuln = self._enhance_single_vulnerability(vuln, code, language)
                enhanced_vulnerabilities.append(enhanced_vuln)
                
                # Rate limiting - wait between requests
                time.sleep(0.5)
                
            except Exception as e:
                # If AI enhancement fails, return original vulnerability
                print(f"AI enhancement failed for {vuln.type}: {str(e)}")
                enhanced_vulnerabilities.append(vuln)
        
        return enhanced_vulnerabilities
    
    def _enhance_single_vulnerability(self, vuln: Vulnerability, code: str, language: str) -> Vulnerability:
        """Enhance a single vulnerability using AI"""
        
        # Create context for AI analysis
        context = self._create_analysis_context(vuln, code, language)
        
        try:
            # Try primary API first
            print(f"[AI] Attempting to enhance: {vuln.type}")
            ai_response = self._query_ai_api(context)
            
            if ai_response:
                print(f"[AI] Got response: {ai_response}")
                enhanced_description = ai_response.get('enhanced_description', vuln.description)
                enhanced_suggestion = ai_response.get('enhanced_suggestion', vuln.suggestion)
                
                # Only use AI response if we got actual content
                if enhanced_description and enhanced_description != vuln.description:
                    print(f"[AI] Using AI-enhanced description")
                    # Create enhanced vulnerability
                    return Vulnerability(
                        vuln_type=vuln.type,
                        severity=vuln.severity,
                        line=vuln.line,
                        description=enhanced_description,
                        code_snippet=vuln.code_snippet,
                        suggestion=enhanced_suggestion,
                        owasp_category=vuln.owasp_category
                    )
                else:
                    print(f"[AI] Response was empty or same as original, using templates")
            else:
                print(f"[AI] No response from API, using templates")
        
        except Exception as e:
            print(f"[AI] API error: {str(e)}")
        
        # If AI enhancement fails, try alternative approach
        print(f"[AI] Falling back to templates for {vuln.type}")
        enhanced_vuln = self._enhance_with_templates(vuln)
        return enhanced_vuln
    
    def _create_analysis_context(self, vuln: Vulnerability, code: str, language: str) -> str:
        """Create context prompt for AI analysis"""
        
        context = f"""
Analyze this {language} security vulnerability:

Vulnerability Type: {vuln.type}
Severity: {vuln.severity}
Line: {vuln.line}
Current Description: {vuln.description}

Vulnerable Code Snippet:
```{language}
{vuln.code_snippet}
```

Please provide:
1. A detailed explanation of why this is vulnerable
2. Specific remediation steps
3. Example of secure code

Focus on practical, actionable advice.
"""
        return context.strip()
    
    def _query_ai_api(self, context: str) -> Optional[Dict[str, str]]:
        """Query Groq API for enhanced analysis"""
        
        if not self.groq_key:
            return None
        
        return self._query_groq_api(context)
    
    def _query_groq_api_for_fix(self, context: str) -> Optional[Dict[str, str]]:
        """Query Groq API specifically for auto-fix generation"""
        
        if not self.groq_key:
            return None
        
        print(f"[GROQ-FIX] Calling Groq API for auto-fix...")
        headers = {
            "Authorization": f"Bearer {self.groq_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code security expert. Your ONLY job is to generate secure code fixes. Return ONLY valid JSON with secure_code, explanation, confidence, and fix_type fields. Do NOT enhance vulnerability descriptions."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.1
        }
        
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    content = result['choices'][0]['message']['content']
                    print(f"[GROQ-FIX] Got response: {content[:200]}...")
                    return {'content': content}
                else:
                    print(f"[GROQ-FIX] No choices in response: {result}")
                    return None
            else:
                print(f"[GROQ-FIX] API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"[GROQ-FIX] Request failed: {str(e)}")
            return None
    
    def _query_groq_api(self, context: str) -> Optional[Dict[str, str]]:
        """Query Groq API for enhanced analysis (OpenAI-compatible format)"""
        
        print(f"[GROQ] Calling Groq API...")
        headers = {
            "Authorization": f"Bearer {self.groq_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",  # Fast and free Llama model
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert. Analyze code vulnerabilities and provide clear, actionable security advice. Be concise and practical."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            "temperature": 0.3,
            "max_tokens": 400,
            "top_p": 1
        }
        
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=20
            )
            
            print(f"[GROQ] Status code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                generated_text = result['choices'][0]['message']['content']
                print(f"[GROQ] Generated text (first 200 chars): {generated_text[:200]}")
                parsed = self._parse_ai_response(generated_text)
                print(f"[GROQ] Parsed response: {parsed}")
                return parsed
            else:
                print(f"[GROQ] API error: {response.status_code} - {response.text[:200]}")
                return None
                
        except requests.exceptions.Timeout:
            print("Groq API timeout - request took too long")
            return None
        except Exception as e:
            print(f"Groq API request failed: {str(e)}")
            return None
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, str]:
        """Parse AI response to extract enhanced description and suggestion"""
        
        # Simple parsing - look for key sections
        lines = response_text.split('\n')
        
        enhanced_description = ""
        enhanced_suggestion = ""
        
        current_section = ""
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Identify sections
            if "explanation" in line.lower() or "why" in line.lower():
                current_section = "description"
                continue
            elif "remediation" in line.lower() or "fix" in line.lower() or "solution" in line.lower():
                current_section = "suggestion"
                continue
            elif "example" in line.lower() and "secure" in line.lower():
                current_section = "suggestion"
                continue
            
            # Add content to appropriate section
            if current_section == "description" and len(enhanced_description) < 300:
                enhanced_description += line + " "
            elif current_section == "suggestion" and len(enhanced_suggestion) < 300:
                enhanced_suggestion += line + " "
        
        return {
            "enhanced_description": enhanced_description.strip() or None,
            "enhanced_suggestion": enhanced_suggestion.strip() or None
        }
    
    def _enhance_with_templates(self, vuln: Vulnerability) -> Vulnerability:
        """Enhance vulnerability using predefined templates as fallback"""
        
        # Template-based enhancements for common vulnerability types
        templates = {
            "SQL Injection": {
                "description": f"{vuln.description} SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization. Attackers can manipulate these queries to access, modify, or delete unauthorized data.",
                "suggestion": f"{vuln.suggestion} Always use parameterized queries or prepared statements. Validate and sanitize all user inputs. Consider using an ORM with built-in protection against SQL injection."
            },
            "Cross-Site Scripting (XSS)": {
                "description": f"{vuln.description} XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users. This can lead to session hijacking, credential theft, or malicious actions on behalf of users.",
                "suggestion": f"{vuln.suggestion} Always encode output, validate inputs, and use Content Security Policy (CSP) headers. Prefer textContent over innerHTML when possible."
            },
            "Code Injection": {
                "description": f"{vuln.description} Code injection vulnerabilities allow attackers to execute arbitrary code on the server or in the browser. This can lead to complete system compromise.",
                "suggestion": f"{vuln.suggestion} Never execute user-provided code. Use whitelisting, input validation, and safer alternatives to eval() and exec()."
            },
            "Hardcoded Credential": {
                "description": f"{vuln.description} Hardcoded credentials in source code can be easily discovered by attackers through code repositories, reverse engineering, or source code access.",
                "suggestion": f"{vuln.suggestion} Use environment variables, secure key management systems, or configuration files that are not committed to version control."
            }
        }
        
        template = templates.get(vuln.type)
        if template:
            return Vulnerability(
                vuln_type=vuln.type,
                severity=vuln.severity,
                line=vuln.line,
                description=template["description"],
                code_snippet=vuln.code_snippet,
                suggestion=template["suggestion"],
                owasp_category=vuln.owasp_category
            )
        
        return vuln
    
    def get_general_security_advice(self, code: str, language: str) -> Dict[str, Any]:
        """Get general security advice for the code"""
        
        if not self.enabled:
            return self._get_template_advice(language)
        
        context = f"""
Provide general security recommendations for this {language} code:

```{language}
{code[:1000]}  # Truncate for API limits
```

Focus on:
1. Security best practices
2. Common vulnerability patterns to watch for
3. Defensive coding recommendations
"""
        
        try:
            response = self._query_ai_api(context)
            if response:
                return {
                    "advice": response.get("enhanced_description", ""),
                    "recommendations": response.get("enhanced_suggestion", "").split(". ") if response.get("enhanced_suggestion") else []
                }
        except Exception as e:
            print(f"General advice query failed: {str(e)}")
        
        return self._get_template_advice(language)
    
    def _get_template_advice(self, language: str) -> Dict[str, Any]:
        """Provide template-based security advice"""
        
        advice_templates = {
            "python": {
                "advice": "Follow Python security best practices including input validation, secure coding patterns, and proper dependency management.",
                "recommendations": [
                    "Use parameterized queries for database operations",
                    "Validate and sanitize all user inputs",
                    "Use secrets module for cryptographic operations",
                    "Keep dependencies updated and scan for vulnerabilities",
                    "Avoid eval(), exec(), and pickle with untrusted data",
                    "Use HTTPS for all network communications",
                    "Implement proper error handling and logging"
                ]
            },
            "javascript": {
                "advice": "Follow JavaScript/Node.js security best practices including XSS prevention, secure coding, and dependency management.",
                "recommendations": [
                    "Sanitize and validate all user inputs",
                    "Use Content Security Policy (CSP) headers",
                    "Avoid innerHTML with user data - use textContent instead",
                    "Never use eval() or Function() with user input",
                    "Use HTTPS and secure cookies",
                    "Implement proper authentication and session management",
                    "Regularly update npm packages and check for vulnerabilities"
                ]
            }
        }
        
        return advice_templates.get(language, {
            "advice": "Follow general secure coding practices for your language.",
            "recommendations": ["Validate inputs", "Use secure libraries", "Keep dependencies updated"]
        })

    def generate_secure_fix(self, vuln: Vulnerability, code: str, language: str) -> Dict[str, Any]:
        """
        Generate a secure code fix for a vulnerability using AI
        
        Args:
            vuln: Vulnerability to fix
            code: Original code
            language: Programming language
            
        Returns:
            Dictionary containing the secure fix and metadata
        """
        if not self.enabled:
            return {
                'secure_code': '',
                'explanation': 'AI fix generation requires GROQ_API_KEY',
                'confidence': 0,
                'fix_type': 'manual'
            }
        
        try:
            # Create prompt for fix generation
            prompt = self._create_fix_generation_prompt(vuln, code, language)
            
            # Get AI response with auto-fix specific system message
            ai_response = self._query_groq_api_for_fix(prompt)
            
            if ai_response:
                # Parse AI response to extract secure code
                fix_data = self._parse_fix_response(ai_response, vuln, code, language)
                return fix_data
            else:
                return {
                    'secure_code': '',
                    'explanation': 'Failed to get AI response for fix generation',
                    'confidence': 0,
                    'fix_type': 'error'
                }
            
        except Exception as e:
            print(f"Error generating fix for {vuln.type}: {str(e)}")
            return {
                'secure_code': '',
                'explanation': f'Failed to generate fix: {str(e)}',
                'confidence': 0,
                'fix_type': 'error'
            }

    def _create_fix_generation_prompt(self, vuln: Vulnerability, code: str, language: str) -> str:
        """Create a prompt for AI to generate secure code fixes"""
        
        prompt = f"""
SECURITY CODE FIX REQUEST - DO NOT ENHANCE VULNERABILITY DESCRIPTION

You are a code security expert. I need you to generate a SECURE CODE FIX for this vulnerability.

VULNERABILITY TO FIX:
- Type: {vuln.type}
- Severity: {vuln.severity}
- Line: {vuln.line}
- Description: {vuln.description}

VULNERABLE CODE:
{vuln.code_snippet}

FULL CODE CONTEXT:
{code}

TASK: Generate a secure version of the vulnerable code that fixes the security issue.

RESPONSE FORMAT - MUST BE VALID JSON ONLY:
{{
    "secure_code": "the_fixed_code_here",
    "explanation": "what_was_changed_and_why",
    "confidence": 8,
    "fix_type": "parameterized_query"
}}

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON
2. Use double quotes for all strings
3. No single quotes anywhere
4. No markdown formatting
5. No code blocks
6. No explanations outside JSON
7. Focus on the SECURE CODE FIX, not vulnerability description

FIX TYPES:
- parameterized_query: SQL injection fixes
- input_validation: Input sanitization
- secure_library: Using secure alternatives
- authentication: Auth-related fixes
- authorization: Permission fixes
- encryption: Encryption/decryption fixes

RESPOND WITH ONLY THE JSON OBJECT:
"""
        return prompt.strip()


    def _parse_fix_response(self, ai_response: Dict[str, str], vuln: Vulnerability, code: str, language: str) -> Dict[str, Any]:
        """Parse AI response to extract secure code fix"""
        
        try:
            # Debug: Print the full response to understand the structure
            print(f"[DEBUG] Full AI response: {ai_response}")
            
            # Try to extract JSON from the response
            response_text = ai_response.get('content', '') or ai_response.get('message', '') or str(ai_response)
            
            print(f"[DEBUG] Response text: {response_text}")
            
            # Check if we got the wrong response format (vulnerability enhancement instead of auto-fix)
            if 'enhanced_description' in response_text or 'enhanced_suggestion' in response_text:
                print(f"[DEBUG] WARNING: Got vulnerability enhancement response instead of auto-fix response!")
                print(f"[DEBUG] This suggests the AI is confused between vulnerability enhancement and auto-fix")
                # Try to extract any useful information from this wrong format
                if 'secure_code' in response_text or 'fixed' in response_text.lower():
                    print(f"[DEBUG] Found potential fix in wrong format, attempting extraction...")
                else:
                    return {
                        'secure_code': '',
                        'explanation': 'AI returned wrong response format (vulnerability enhancement instead of auto-fix)',
                        'confidence': 0,
                        'fix_type': 'format_error'
                    }
            
            # Look for JSON in the response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(0)
                print(f"[DEBUG] Found JSON: {json_str}")
                
                try:
                    fix_data = json.loads(json_str)
                    
                    # Validate the response structure
                    if 'secure_code' in fix_data:
                        return {
                            'secure_code': fix_data.get('secure_code', ''),
                            'explanation': fix_data.get('explanation', 'AI-generated secure fix'),
                            'confidence': fix_data.get('confidence', 5),
                            'fix_type': fix_data.get('fix_type', 'ai_generated')
                        }
                except json.JSONDecodeError as e:
                    print(f"[DEBUG] JSON parsing failed: {e}")
                    print(f"[DEBUG] Malformed JSON: {json_str}")
                    
                    # Try to fix common JSON issues
                    try:
                        # Fix common issues like single quotes, trailing commas, etc.
                        fixed_json = json_str.replace("'", '"')  # Replace single quotes with double quotes
                        fixed_json = re.sub(r',\s*}', '}', fixed_json)  # Remove trailing commas
                        fixed_json = re.sub(r',\s*]', ']', fixed_json)  # Remove trailing commas in arrays
                        
                        fix_data = json.loads(fixed_json)
                        if 'secure_code' in fix_data:
                            return {
                                'secure_code': fix_data.get('secure_code', ''),
                                'explanation': fix_data.get('explanation', 'AI-generated secure fix'),
                                'confidence': fix_data.get('confidence', 5),
                                'fix_type': fix_data.get('fix_type', 'ai_generated')
                            }
                    except json.JSONDecodeError:
                        print(f"[DEBUG] Fixed JSON still invalid, trying alternative parsing")
                        pass
            
            # If no JSON found, try to extract code from markdown
            code_match = re.search(r'```(?:python|javascript|js)?\n(.*?)\n```', response_text, re.DOTALL)
            if code_match:
                print(f"[DEBUG] Found code in markdown: {code_match.group(1)}")
                return {
                    'secure_code': code_match.group(1).strip(),
                    'explanation': 'AI-generated secure fix (parsed from response)',
                    'confidence': 6,
                    'fix_type': 'ai_generated'
                }
            
            # Try to find any code blocks without language specification
            code_match_generic = re.search(r'```\n(.*?)\n```', response_text, re.DOTALL)
            if code_match_generic:
                print(f"[DEBUG] Found generic code block: {code_match_generic.group(1)}")
                return {
                    'secure_code': code_match_generic.group(1).strip(),
                    'explanation': 'AI-generated secure fix (parsed from generic code block)',
                    'confidence': 5,
                    'fix_type': 'ai_generated'
                }
            
            # Try to extract code from lines that look like code
            lines = response_text.split('\n')
            code_lines = []
            in_code_block = False
            
            for line in lines:
                if line.strip().startswith('```'):
                    in_code_block = not in_code_block
                    continue
                if in_code_block:
                    code_lines.append(line)
            
            if code_lines:
                print(f"[DEBUG] Found code in lines: {code_lines}")
                return {
                    'secure_code': '\n'.join(code_lines).strip(),
                    'explanation': 'AI-generated secure fix (parsed from code lines)',
                    'confidence': 4,
                    'fix_type': 'ai_generated'
                }
            
            # Advanced fallback: try to extract any code from the response
            print(f"[DEBUG] Using advanced fallback parsing")
            
            # Try to find any code-like content
            lines = response_text.split('\n')
            potential_code = []
            in_code_section = False
            
            for line in lines:
                line = line.strip()
                # Look for lines that look like code
                if (line and 
                    not line.startswith('#') and 
                    not line.startswith('//') and 
                    not line.startswith('*') and
                    not line.startswith('```') and
                    not line.startswith('{') and
                    not line.startswith('}') and
                    ('=' in line or '(' in line or 'def ' in line or 'import ' in line or 'from ' in line or 'if ' in line or 'for ' in line or 'while ' in line or 'class ' in line)):
                    potential_code.append(line)
            
            if potential_code:
                print(f"[DEBUG] Found potential code: {potential_code}")
                return {
                    'secure_code': '\n'.join(potential_code),
                    'explanation': 'AI-generated secure fix (extracted from response)',
                    'confidence': 4,
                    'fix_type': 'ai_generated'
                }
            
            # Final fallback: return the full response as explanation
            print(f"[DEBUG] Using final fallback - full response as explanation")
            return {
                'secure_code': '',
                'explanation': response_text[:500] + ('...' if len(response_text) > 500 else ''),
                'confidence': 3,
                'fix_type': 'explanation_only'
            }
            
        except Exception as e:
            print(f"Error parsing fix response: {str(e)}")
            return {
                'secure_code': '',
                'explanation': f'Failed to parse AI response: {str(e)}',
                'confidence': 0,
                'fix_type': 'error'
            }