# Web-Based AI Coding Assistant

A sophisticated web application that combines security analysis with AI-powered code review for Python and JavaScript. This tool helps developers identify and fix security vulnerabilities while providing intelligent suggestions for code improvement.

## 🌟 Features

### Code Analysis
- **Multi-Language Support**:
  - Python code analysis
  - JavaScript code analysis
  - Language-specific security rules
  - Syntax highlighting for both languages

### Security Analysis
- **OWASP Top 10 Vulnerability Detection**:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - Insecure Deserialization
  - And more...

### AI Integration
- **Groq-Powered Analysis**:
  - AI-enhanced vulnerability descriptions using Llama 3.3 70B
  - Contextual security recommendations
  - Code improvement suggestions
  - Fast and accurate analysis
  - Automatic fallback to templates if API unavailable

### File Handling
- **Multiple Input Methods**:
  - Direct code input via web editor
  - Single file upload (.py files)
  - Project upload (ZIP files, Python only)
  - Maximum file size: 10MB (configurable)

### User Interface
- **Modern Web Interface**:
  - Real-time code editor
  - Syntax highlighting
  - Interactive results display
  - Responsive design
  - Clean and intuitive layout

## 🏗 Project Structure
```
AI-Coding-Assistant/
├── main/
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── ai_analyzer.py      # AI-powered code analysis
│   │   └── security_analyzer.py # Security vulnerability detection
│   ├── static/
│   │   ├── app.js             # Frontend JavaScript
│   │   └── styles.css         # CSS styles
│   ├── templates/
│   │   └── index.html         # Main web interface
│   ├── uploads/               # Temporary file storage
│   ├── app.py                # Flask application
│   └── config.py             # Configuration settings
├── requirements.txt          # Python dependencies
└── README.md                # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser
- Internet connection (for AI features)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/VictorChanKaiWen/AI-Coding-Assistant.git
   cd AI-Coding-Assistant
   ```

2. Create and configure environment variables:
   ```bash
   # Create .env file with required settings
   # AI-enhanced analysis (RECOMMENDED):
   GROQ_API_KEY=your_groq_api_key_here  # Get free key at https://console.groq.com
   
   # App settings
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here
   MAX_CODE_LENGTH=10000
   MAX_FILE_SIZE=10485760
   ```
   
   **Note**: See [GROQ_SETUP.md](GROQ_SETUP.md) for detailed AI setup instructions.

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:
   ```bash
   python main/app.py
   ```

5. Access the web interface:
   - Open `http://localhost:5000` in your browser

## 💻 Usage

### Direct Code Analysis
1. Select language (Python/JavaScript)
2. Paste code into the editor
3. Click "Analyze Code"
4. Review security analysis results

### File Upload (Python Only)
1. Select a .py file or .zip project
2. Click "Choose File"
3. Click "Analyze File"
4. Review comprehensive analysis results

### Understanding Results
- Severity levels (HIGH, MEDIUM, LOW)
- Vulnerability descriptions
- AI-enhanced explanations
- Remediation suggestions
- Code snippets with highlights

## 🔧 Configuration

### Environment Variables
- `GROQ_API_KEY`: Groq API key for AI analysis
- `MAX_CODE_LENGTH`: Maximum code input length
- `MAX_FILE_SIZE`: Maximum upload file size
- `FLASK_ENV`: Development environment
- `SECRET_KEY`: Flask session security

### Security Settings
- Configurable file extensions
- Upload size limits
- Analysis timeouts
- AI enhancement options

## 🛠 Technical Details

### Backend
- **Framework**: Flask
- **Security Analysis**: Custom Python modules
- **AI Integration**: Groq API (Llama 3.3 70B)
- **File Processing**: Python standard library

### Frontend
- **Editor**: CodeMirror
- **Styling**: Custom CSS
- **Interactivity**: Vanilla JavaScript
- **Syntax Highlighting**: Prism.js

### AI Features
- **Model**: Llama 3.3 70B (via Groq)
- **Capabilities**:
  - AI-powered vulnerability analysis
  - Context-aware security recommendations
  - Detailed remediation guidance
  - Fast inference (~1 second per vulnerability)

## 🔐 Security Features

### Input Validation
- File type verification
- Size limit enforcement
- Code length restrictions
- Secure file handling

### Analysis Capabilities
- OWASP Top 10 coverage
- Language-specific rules
- AI-enhanced detection
- Comprehensive reporting

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Implement changes
4. Submit pull request

### Guidelines
- Follow PEP 8 for Python code
- Document new features
- Add tests for new functionality
- Maintain code quality

## 📝 License
Open source under MIT License

## 🚧 Development Status
Currently in active development. Features and improvements are regularly added.

## 🔮 Future Plans
- Additional language support
- Enhanced AI capabilities
- Real-time collaboration
- Custom rule creation
- Performance optimizations