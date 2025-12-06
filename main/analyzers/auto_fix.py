"""
Auto-Fix Module for Security Vulnerabilities
Generates secure code fixes using AI
"""

from typing import Dict, Any
from .security_analyzer import Vulnerability

class AutoFixGenerator:
    """Generates automatic fixes for security vulnerabilities"""
    
    def __init__(self, security_analyzer):
        self.security_analyzer = security_analyzer
    
    def generate_auto_fix(self, vulnerability: Vulnerability, code: str, language: str) -> Dict[str, Any]:
        """
        Generate an automatic fix for a vulnerability using AI
        
        Args:
            vulnerability: The vulnerability to fix
            code: The original code
            language: Programming language
            
        Returns:
            Dictionary containing the secure fix and metadata
        """
        if not self.security_analyzer.ai_analyzer:
            return {
                'secure_code': '',
                'explanation': 'AI analyzer not available for auto-fix generation',
                'confidence': 0,
                'fix_type': 'manual'
            }
        
        try:
            # Use AI analyzer to generate secure fix
            fix_data = self.security_analyzer.ai_analyzer.generate_secure_fix(vulnerability, code, language)
            return fix_data
            
        except Exception as e:
            print(f"Error generating auto-fix: {str(e)}")
            return {
                'secure_code': '',
                'explanation': f'Failed to generate auto-fix: {str(e)}',
                'confidence': 0,
                'fix_type': 'error'
            }
