import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration settings for the Secure Coding Assistant"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    
    # AI API settings (Groq)
    GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
    
    # Security settings
    MAX_CODE_LENGTH = int(os.environ.get('MAX_CODE_LENGTH', 10000))
    ALLOWED_EXTENSIONS = os.environ.get('ALLOWED_EXTENSIONS', 'py,js,ts,jsx,tsx').split(',')
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB default
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    
    # Analysis settings
    ENABLE_AI_ANALYSIS = bool(GROQ_API_KEY)
    ANALYSIS_TIMEOUT = 30  # seconds