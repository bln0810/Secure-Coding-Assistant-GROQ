from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import sys
import traceback
import zipfile
import tempfile
import shutil
from werkzeug.utils import secure_filename

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from analyzers.security_analyzer import SecurityAnalyzer
from project_manager import ProjectManager

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for all routes
CORS(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the security analyzer and project manager
security_analyzer = SecurityAnalyzer()
project_manager = ProjectManager()

@app.after_request
def add_header(response):
    """Add headers to prevent caching of static files in development"""
    if app.config['FLASK_ENV'] == 'development':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    """Index/landing page route"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard route - shows project list"""
    return render_template('dashboard.html')

@app.route('/project/<project_id>')
def project_page(project_id):
    """Project analysis page for a specific project"""
    project = project_manager.get_project(project_id)
    if not project:
        return render_template('dashboard.html'), 404
    return render_template('project.html', project_id=project_id, project_name=project.get('name', 'Project'))

@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    """API endpoint for code analysis"""
    try:
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        code = data.get('code', '').strip()
        language = data.get('language', 'python').lower()
        
        # Validate input
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        
        if len(code) > app.config['MAX_CODE_LENGTH']:
            return jsonify({
                'error': f'Code too long. Maximum length is {app.config["MAX_CODE_LENGTH"]} characters.'
            }), 400
        
        if language not in ['python', 'javascript', 'js']:
            return jsonify({'error': 'Unsupported language'}), 400
        
        # Normalize language
        if language == 'js':
            language = 'javascript'
        
        # Perform analysis
        analysis_result = security_analyzer.analyze(code, language)
        
        # Save to project if project_id is provided
        project_id = data.get('project_id')
        if project_id:
            try:
                project_manager.add_analysis(project_id, analysis_result)
            except Exception as e:
                app.logger.warning(f"Failed to save analysis to project: {str(e)}")
        
        return jsonify(analysis_result)
    
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        return jsonify({
            'error': 'Internal server error during analysis',
            'details': str(e) if app.debug else 'Please try again later'
        }), 500

@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    """API endpoint for file/zip upload analysis"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > app.config['MAX_FILE_SIZE']:
            return jsonify({
                'error': f'File too large. Maximum size is {app.config["MAX_FILE_SIZE"] / (1024*1024):.1f}MB'
            }), 400
        
        filename = secure_filename(file.filename)
        
        # Create temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            
            # Check if it's a zip file
            if filename.lower().endswith('.zip'):
                results = analyze_zip_file(file_path, temp_dir)
            elif filename.lower().endswith('.py'):
                # Single Python file
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                results = {
                    'files': [{
                        'filename': filename,
                        'analysis': security_analyzer.analyze(code, 'python'),
                        'code': code
                    }]
                }
            else:
                return jsonify({'error': 'Unsupported file type. Please upload a .py or .zip file'}), 400
            
            # Add summary statistics
            results['summary'] = calculate_overall_summary(results.get('files', []))
            
            # Save to project if project_id is provided
            project_id = request.form.get('project_id')
            if project_id:
                try:
                    project_manager.add_analysis(project_id, results)
                except Exception as e:
                    app.logger.warning(f"Failed to save analysis to project: {str(e)}")
            
            return jsonify(results)
    
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid zip file'}), 400
    except UnicodeDecodeError:
        return jsonify({'error': 'File encoding error. Please ensure files are UTF-8 encoded'}), 400
    except Exception as e:
        app.logger.error(f"File analysis error: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        return jsonify({
            'error': 'Internal server error during file analysis',
            'details': str(e) if app.debug else 'Please try again later'
        }), 500

def analyze_zip_file(zip_path, extract_dir):
    """Extract and analyze all Python files in a zip archive"""
    results = {'files': []}
    
    # Extract zip file
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    # Find all Python files
    python_files = []
    for root, dirs, files in os.walk(extract_dir):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'venv', 'env', 'node_modules', '.venv']]
        
        for file in files:
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, extract_dir)
                python_files.append((relative_path, full_path))
    
    if not python_files:
        results['warning'] = 'No Python files found in the zip archive'
        return results
    
    # Analyze each Python file
    for relative_path, full_path in python_files:
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Skip empty files or files that are too large
            if not code.strip() or len(code) > app.config['MAX_CODE_LENGTH']:
                print(f"[ZIP] Skipping {relative_path} - empty or too large")
                continue
            
            print(f"[ZIP] Analyzing {relative_path}...")
            analysis = security_analyzer.analyze(code, 'python')
            vuln_count = len(analysis.get('vulnerabilities', []))
            print(f"[ZIP] Found {vuln_count} vulnerabilities in {relative_path}")
            
            # Include all analyzed files
            results['files'].append({
                'filename': relative_path,
                'analysis': analysis,
                'code': code
            })
        
        except Exception as e:
            app.logger.warning(f"Error analyzing {relative_path}: {str(e)}")
            print(f"[ZIP] Error analyzing {relative_path}: {str(e)}")
            continue
    
    return results

def calculate_overall_summary(files):
    """Calculate overall statistics across all analyzed files"""
    total_high = 0
    total_medium = 0
    total_low = 0
    total_issues = 0
    files_with_issues = 0
    
    for file_data in files:
        analysis = file_data.get('analysis', {})
        summary = analysis.get('summary', {})
        
        total_high += summary.get('high', 0)
        total_medium += summary.get('medium', 0)
        total_low += summary.get('low', 0)
        total_issues += summary.get('total_issues', 0)
        
        if summary.get('total_issues', 0) > 0:
            files_with_issues += 1
    
    return {
        'total_files': len(files),
        'files_with_issues': files_with_issues,
        'high': total_high,
        'medium': total_medium,
        'low': total_low,
        'total_issues': total_issues
    }

@app.route('/api/generate-fix', methods=['POST'])
def generate_fix():
    """API endpoint for generating automatic fixes for vulnerabilities"""
    try:
        # Get request data
        data = request.get_json()
        app.logger.info(f"Auto-fix request data: {data}")
        
        if not data:
            app.logger.error("No data provided in request")
            return jsonify({'error': 'No data provided'}), 400
        
        vulnerability_data = data.get('vulnerability')
        code = data.get('code', '').strip()
        language = data.get('language', 'python').lower()
        
        app.logger.info(f"Parsed data - vulnerability: {bool(vulnerability_data)}, code length: {len(code)}, language: {language}")
        
        # Validate input
        if not vulnerability_data:
            app.logger.error("No vulnerability data provided")
            return jsonify({'error': 'No vulnerability data provided'}), 400
        
        if not code:
            app.logger.error("No code provided")
            return jsonify({'error': 'No code provided'}), 400
        
        if language not in ['python', 'javascript', 'js']:
            app.logger.error(f"Unsupported language: {language}")
            return jsonify({'error': f'Unsupported language: {language}'}), 400
        
        # Normalize language
        if language == 'js':
            language = 'javascript'
        
        # Create vulnerability object
        from analyzers.security_analyzer import Vulnerability
        vulnerability = Vulnerability(
            vuln_type=vulnerability_data.get('type', ''),
            severity=vulnerability_data.get('severity', 'medium'),
            line=vulnerability_data.get('line', 0),
            description=vulnerability_data.get('description', ''),
            code_snippet=vulnerability_data.get('code_snippet', ''),
            suggestion=vulnerability_data.get('suggestion', ''),
            owasp_category=vulnerability_data.get('owasp_category', '')
        )
        
        # Generate auto-fix
        from analyzers.auto_fix import AutoFixGenerator
        auto_fix_generator = AutoFixGenerator(security_analyzer)
        fix_data = auto_fix_generator.generate_auto_fix(vulnerability, code, language)
        
        return jsonify(fix_data)
    
    except Exception as e:
        app.logger.error(f"Auto-fix generation error: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        return jsonify({
            'error': 'Internal server error during fix generation',
            'details': str(e) if app.debug else 'Please try again later'
        }), 500

@app.route('/api/test-ai', methods=['POST'])
def test_ai():
    """Test endpoint to debug AI responses"""
    try:
        data = request.get_json()
        test_prompt = data.get('prompt', 'Test prompt')
        
        if not security_analyzer.ai_analyzer:
            return jsonify({'error': 'AI analyzer not available'}), 400
        
        # Test the AI with a simple prompt
        response = security_analyzer.ai_analyzer._query_groq_api(test_prompt)
        
        return jsonify({
            'prompt': test_prompt,
            'response': response,
            'response_type': type(response).__name__,
            'response_keys': list(response.keys()) if isinstance(response, dict) else 'Not a dict'
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/projects', methods=['GET'])
def get_projects():
    """Get all projects"""
    try:
        projects = project_manager.get_all_projects()
        return jsonify(projects)
    except Exception as e:
        app.logger.error(f"Error getting projects: {str(e)}")
        return jsonify({'error': 'Failed to retrieve projects'}), 500

@app.route('/api/projects', methods=['POST'])
def create_project():
    """Create a new project"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Project name is required'}), 400
        
        description = data.get('description', '').strip()
        project = project_manager.create_project(name, description)
        return jsonify(project), 201
    except Exception as e:
        app.logger.error(f"Error creating project: {str(e)}")
        return jsonify({'error': 'Failed to create project'}), 500

@app.route('/api/projects/<project_id>', methods=['GET'])
def get_project(project_id):
    """Get a specific project"""
    try:
        project = project_manager.get_project(project_id)
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        return jsonify(project)
    except Exception as e:
        app.logger.error(f"Error getting project: {str(e)}")
        return jsonify({'error': 'Failed to retrieve project'}), 500

@app.route('/api/projects/<project_id>', methods=['DELETE'])
def delete_project(project_id):
    """Delete a project"""
    try:
        success = project_manager.delete_project(project_id)
        if not success:
            return jsonify({'error': 'Project not found'}), 404
        return jsonify({'message': 'Project deleted successfully'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting project: {str(e)}")
        return jsonify({'error': 'Failed to delete project'}), 500

@app.route('/api/projects/<project_id>', methods=['PATCH'])
def update_project(project_id):
    """Update a project (e.g., toggle favorite)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        project = project_manager.update_project(project_id, data)
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        return jsonify(project)
    except Exception as e:
        app.logger.error(f"Error updating project: {str(e)}")
        return jsonify({'error': 'Failed to update project'}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        projects = project_manager.get_all_projects()
        
        total_projects = len(projects)
        total_analyses = sum(len(p.get('analyses', [])) for p in projects)
        
        total_high = 0
        total_medium = 0
        total_low = 0
        projects_with_issues = 0
        
        for project in projects:
            if project.get('latest_analysis'):
                summary = project.get('latest_analysis', {}).get('summary', {})
                total_high += summary.get('high', 0)
                total_medium += summary.get('medium', 0)
                total_low += summary.get('low', 0)
                if summary.get('total_issues', 0) > 0:
                    projects_with_issues += 1
        
        return jsonify({
            'total_projects': total_projects,
            'total_analyses': total_analyses,
            'total_high': total_high,
            'total_medium': total_medium,
            'total_low': total_low,
            'total_issues': total_high + total_medium + total_low,
            'projects_with_issues': projects_with_issues
        })
    except Exception as e:
        app.logger.error(f"Error getting dashboard stats: {str(e)}")
        return jsonify({'error': 'Failed to retrieve stats'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '0.1.0',
        'ai_enabled': app.config['ENABLE_AI_ANALYSIS']
    })

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create .env file from example if it doesn't exist
    if not os.path.exists('.env') and os.path.exists('.env.example'):
        import shutil
        shutil.copy('.env.example', '.env')
        print("Created .env file from .env.example")
        print("Please edit .env file with your API keys and settings")
    
    # Run the application
    debug_mode = app.config['FLASK_ENV'] == 'development'
    
    print("Starting Secure Coding Assistant...")
    print(f"Debug mode: {debug_mode}")
    print(f"AI Analysis: {'Enabled' if app.config['ENABLE_AI_ANALYSIS'] else 'Disabled (add HF_API_TOKEN to enable)'}")
    print("Server running at: http://localhost:5000")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode
    )