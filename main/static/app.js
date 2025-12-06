// Secure Coding Assistant - Frontend JavaScript
class SecureCodingAssistant {
    constructor() {
        // Get project_id from URL if present
        const pathParts = window.location.pathname.split('/');
        this.projectId = pathParts.length > 2 && pathParts[1] === 'project' ? pathParts[2] : null;
        
        // Real-time analysis settings
        this.realTimeAnalysisEnabled = true;
        this.analysisDebounceTimer = null;
        this.analysisDebounceDelay = 1500; // 1.5 seconds after user stops typing
        this.isAnalyzing = false;
        this.currentMarkers = [];
        this.currentGutterMarkers = [];
        
        this.initializeElements();
        this.attachEventListeners();
        this.setupRealTimeAnalysis();
    }

    initializeElements() {
        this.languageSelect = document.getElementById('language-select');
        this.analyzeBtn = document.getElementById('analyze-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.resultsContainer = document.getElementById('results-container');
        this.loading = document.getElementById('loading');
        this.fileInput = document.getElementById('file-input');
        this.uploadBtn = document.getElementById('upload-btn');
        this.analyzeFileBtn = document.getElementById('analyze-file-btn');
        this.fileNameDisplay = document.getElementById('file-name');
        this.uploadSection = document.getElementById('upload-section');
        this.selectedFile = null;
        
        // Show/hide upload section based on initial language selection
        this.toggleUploadSection(this.languageSelect.value);
        
        // Initialize CodeMirror
        this.editor = CodeMirror(document.getElementById('code-editor'), {
            mode: 'python',  // default mode
            theme: 'monokai',
            lineNumbers: true,
            indentUnit: 4,
            tabSize: 4,
            indentWithTabs: false,
            autofocus: true,
            lineWrapping: true,
            foldGutter: true,
            gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter", "vulnerability-markers"],
            extraKeys: {
                "Ctrl-Enter": () => this.analyzeCode()
            }
        });
    }

    attachEventListeners() {
        this.analyzeBtn.addEventListener('click', () => this.analyzeCode());
        this.clearBtn.addEventListener('click', () => this.clearCode());
        
        // Update editor mode when language changes
        this.languageSelect.addEventListener('change', () => {
            const mode = this.languageSelect.value === 'python' ? 'python' : 'javascript';
            this.editor.setOption('mode', mode);
            this.toggleUploadSection(this.languageSelect.value);
            // Clear markers when language changes
            this.clearMarkers();
        });
        
        // File upload event listeners
        this.uploadBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.analyzeFileBtn.addEventListener('click', () => this.analyzeFile());
        
        // Real-time analysis toggle
        const realtimeToggle = document.getElementById('realtime-toggle');
        if (realtimeToggle) {
            realtimeToggle.addEventListener('change', (e) => {
                this.realTimeAnalysisEnabled = e.target.checked;
                if (!this.realTimeAnalysisEnabled) {
                    // Cancel any pending analysis
                    if (this.analysisDebounceTimer) {
                        clearTimeout(this.analysisDebounceTimer);
                        this.analysisDebounceTimer = null;
                    }
                    this.updateAnalysisStatus('idle', '');
                } else {
                    // If real-time is enabled and there's code in the editor, analyze it immediately
                    const code = this.editor.getValue().trim();
                    if (code && code.length >= 10) {
                        // Trigger immediate analysis of existing code
                        this.performRealTimeAnalysis();
                    }
                }
            });
        }
    }

    setupRealTimeAnalysis() {
        // Listen for code changes in the editor
        this.editor.on('change', () => {
            if (this.realTimeAnalysisEnabled) {
                this.scheduleRealTimeAnalysis();
            }
        });
    }

    scheduleRealTimeAnalysis() {
        // Clear existing timer
        if (this.analysisDebounceTimer) {
            clearTimeout(this.analysisDebounceTimer);
        }

        // Clear existing markers while typing
        this.clearMarkers();
        this.updateAnalysisStatus('typing', 'Typing...');

        // Schedule new analysis
        this.analysisDebounceTimer = setTimeout(() => {
            this.performRealTimeAnalysis();
        }, this.analysisDebounceDelay);
    }

    async performRealTimeAnalysis() {
        const code = this.editor.getValue().trim();
        const language = this.languageSelect.value;

        // Don't analyze empty code
        if (!code || code.length < 10) {
            this.clearMarkers();
            this.updateAnalysisStatus('idle', '');
            // Clear results panel for very short code
            this.resultsContainer.innerHTML = `
                <div class="placeholder">
                    <p>No analysis results yet. Submit some code to get started!</p>
                </div>
            `;
            return;
        }

        // Don't analyze if already analyzing
        if (this.isAnalyzing) {
            return;
        }

        this.isAnalyzing = true;
        this.updateAnalysisStatus('analyzing', 'Analyzing...');

        try {
            const requestBody = {
                code: code,
                language: language
            };
            
            if (this.projectId) {
                requestBody.project_id = this.projectId;
            }
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            
            if (result.error) {
                this.updateAnalysisStatus('error', 'Analysis error');
                return;
            }

            // Display vulnerabilities in editor
            this.displayVulnerabilitiesInEditor(result);
            
            // Display full results in results panel
            this.displayResults(result);
            
            // Update status
            const vulnCount = (result.vulnerabilities || []).length;
            if (vulnCount > 0) {
                this.updateAnalysisStatus('issues', `${vulnCount} issue${vulnCount > 1 ? 's' : ''} found`);
            } else {
                this.updateAnalysisStatus('clean', 'No issues found');
            }

        } catch (error) {
            console.error('Real-time analysis failed:', error);
            this.updateAnalysisStatus('error', 'Analysis failed');
        } finally {
            this.isAnalyzing = false;
        }
    }

    displayVulnerabilitiesInEditor(result) {
        this.clearMarkers();
        
        const vulnerabilities = result.vulnerabilities || [];
        
        vulnerabilities.forEach(vuln => {
            if (vuln.line && vuln.line > 0) {
                const lineIndex = vuln.line - 1; // CodeMirror uses 0-based indexing
                const severity = vuln.severity.toLowerCase();
                
                // Get line handle
                const lineHandle = this.editor.getLineHandle(lineIndex);
                if (!lineHandle) return;
                
                // Add line marker (highlighting)
                this.editor.addLineClass(lineHandle, 'background', `vulnerability-line-${severity}`);
                this.currentMarkers.push({ line: lineIndex, handle: lineHandle, severity: severity });
                
                // Add gutter marker
                const gutterMarker = document.createElement('div');
                gutterMarker.className = `gutter-marker gutter-marker-${severity}`;
                gutterMarker.title = `${vuln.severity}: ${vuln.type}`;
                this.editor.setGutterMarker(lineHandle, 'vulnerability-markers', gutterMarker);
                this.currentGutterMarkers.push({ line: lineIndex, handle: lineHandle, marker: gutterMarker });
                
                // Store vulnerability data for tooltip
                lineHandle.vulnerability = vuln;
            }
        });
    }


    clearMarkers() {
        // Clear line markers
        this.currentMarkers.forEach(({ handle, severity }) => {
            try {
                this.editor.removeLineClass(handle, 'background', `vulnerability-line-${severity}`);
            } catch (e) {
                // Line may have been deleted, ignore
            }
        });
        this.currentMarkers = [];
        
        // Clear gutter markers
        this.currentGutterMarkers.forEach(({ handle }) => {
            try {
                this.editor.setGutterMarker(handle, 'vulnerability-markers', null);
            } catch (e) {
                // Line may have been deleted, ignore
            }
        });
        this.currentGutterMarkers = [];
    }

    updateAnalysisStatus(status, message) {
        // Create or update status indicator
        let statusIndicator = document.getElementById('realtime-status');
        
        if (!statusIndicator) {
            statusIndicator = document.createElement('div');
            statusIndicator.id = 'realtime-status';
            statusIndicator.className = 'realtime-status';
            
            // Insert after controls
            const controls = document.querySelector('.controls');
            if (controls) {
                controls.insertAdjacentElement('afterend', statusIndicator);
            }
        }
        
        // Update status classes and message
        statusIndicator.className = `realtime-status status-${status}`;
        statusIndicator.textContent = message;
        
        // Add icon based on status
        const icons = {
            'typing': '⌨️',
            'analyzing': '⏳',
            'issues': '⚠️',
            'clean': '✅',
            'error': '❌',
            'idle': ''
        };
        
        if (icons[status]) {
            statusIndicator.innerHTML = `${icons[status]} ${message}`;
        }
        
        // Hide if idle
        if (status === 'idle' || !message) {
            statusIndicator.style.display = 'none';
        } else {
            statusIndicator.style.display = 'flex';
        }
    }

    async analyzeCode() {
        const code = this.editor.getValue().trim();
        const language = this.languageSelect.value;

        if (!code) {
            this.showError('Please enter some code to analyze.');
            return;
        }

        // Cancel any pending real-time analysis
        if (this.analysisDebounceTimer) {
            clearTimeout(this.analysisDebounceTimer);
            this.analysisDebounceTimer = null;
        }

        this.showLoading(true);
        this.analyzeBtn.disabled = true;
        this.updateAnalysisStatus('analyzing', 'Analyzing...');

        try {
            const requestBody = {
                code: code,
                language: language
            };
            
            // Include project_id if available
            if (this.projectId) {
                requestBody.project_id = this.projectId;
            }
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            
            // Display vulnerabilities in editor
            this.displayVulnerabilitiesInEditor(result);
            
            // Display full results in results panel
            this.displayResults(result);
            
            // Update status
            const vulnCount = (result.vulnerabilities || []).length;
            if (vulnCount > 0) {
                this.updateAnalysisStatus('issues', `${vulnCount} issue${vulnCount > 1 ? 's' : ''} found`);
            } else {
                this.updateAnalysisStatus('clean', 'No issues found');
            }
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showError('Analysis failed. Please check your connection and try again.');
            this.updateAnalysisStatus('error', 'Analysis failed');
        } finally {
            this.showLoading(false);
            this.analyzeBtn.disabled = false;
        }
    }

    toggleUploadSection(language) {
        if (language === 'python') {
            this.uploadSection.style.display = 'block';
        } else {
            this.uploadSection.style.display = 'none';
            // Clear any selected file when switching to JavaScript
            this.selectedFile = null;
            this.fileNameDisplay.textContent = '';
            this.analyzeFileBtn.style.display = 'none';
            this.fileInput.value = '';
        }
    }

    displayResults(result) {
        if (result.error) {
            this.showError(result.error);
            return;
        }

        const vulnerabilities = result.vulnerabilities || [];
        const summary = result.summary || {};

        let html = '';

        // Analysis summary
        if (summary.total_issues > 0) {
            html += this.createSummaryHTML(summary);
        }

        // Vulnerabilities
        if (vulnerabilities.length > 0) {
            html += vulnerabilities.map(vuln => this.createVulnerabilityHTML(vuln)).join('');
        } else {
            html += `
                <div class="analysis-summary">
                    <div style="text-align: center; color: #28a745;">
                        <h3>✅ No Security Issues Found!</h3>
                        <p>Your code appears to be free from common security vulnerabilities.</p>
                    </div>
                </div>
            `;
        }

        this.resultsContainer.innerHTML = html;
        this.attachVulnerabilityEventListeners();
    }

    createSummaryHTML(summary) {
        return `
            <div class="analysis-summary">
                <h3>Analysis Summary</h3>
                <div class="summary-stats">
                    <div class="stat-item">
                        <span class="stat-number" style="color: #ff4757;">${summary.high || 0}</span>
                        <span class="stat-label">High</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" style="color: #ffa726;">${summary.medium || 0}</span>
                        <span class="stat-label">Medium</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" style="color: #66bb6a;">${summary.low || 0}</span>
                        <span class="stat-label">Low</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">${summary.total_issues || 0}</span>
                        <span class="stat-label">Total Issues</span>
                    </div>
                </div>
            </div>
        `;
    }

    createVulnerabilityHTML(vulnerability) {
        const severityClass = `severity-${vulnerability.severity.toLowerCase()}`;
        const vulnId = `vuln-${Math.random().toString(36).substr(2, 9)}`;
        
        return `
            <div class="vulnerability">
                <div class="vulnerability-header" data-target="${vulnId}">
                    <div class="vulnerability-info">
                        <span class="severity-badge ${severityClass}">${vulnerability.severity}</span>
                        <span class="vulnerability-title">${vulnerability.type}</span>
                        ${vulnerability.line ? `<span class="line-number">Line ${vulnerability.line}</span>` : ''}
                    </div>
                    <span class="expand-arrow">▼</span>
                </div>
                <div class="vulnerability-details" id="${vulnId}">
                    <div class="vulnerability-description">
                        ${this.formatVulnerabilityDescription(vulnerability.description)}
                    </div>
                    ${vulnerability.code_snippet ? `
                        <div class="code-snippet">
                            <h4>📋 Code Snippet</h4>
                            <pre><code>${this.escapeHtml(vulnerability.code_snippet)}</code></pre>
                        </div>
                    ` : ''}
                    ${vulnerability.suggestion ? `
                        <div class="suggestion">
                            <h4>Recommendation</h4>
                            <div>${this.formatVulnerabilityDescription(vulnerability.suggestion)}</div>
                        </div>
                    ` : ''}
                    ${vulnerability.owasp_category ? `
                        <div style="margin-top: 15px; padding: 10px; background: #e7f3ff; border-left: 4px solid #007bff;">
                            <strong>OWASP Category:</strong> ${vulnerability.owasp_category}
                        </div>
                    ` : ''}
                    <div class="auto-fix-section" style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e9ecef;">
                        <button class="btn btn-primary auto-fix-btn" data-vuln-id="${vulnId}" style="margin-bottom: 10px;">
                            🔧 Generate Auto-Fix
                        </button>
                        <div class="auto-fix-result" id="fix-${vulnId}" style="display: none;">
                            <div class="fix-loading" style="display: none; text-align: center; padding: 20px;">
                                <div class="spinner"></div>
                                <p>Generating secure fix...</p>
                            </div>
                            <div class="fix-content" style="display: none;">
                                <h4>🔒 Secure Code Fix</h4>
                                <div class="code-comparison">
                                    <div class="code-before">
                                        <h5>❌ Vulnerable Code</h5>
                                        <pre><code class="vulnerable-code"></code></pre>
                                    </div>
                                    <div class="code-after">
                                        <div class="secure-code-header">
                                            <h5>✅ Secure Code</h5>
                                            <button class="btn btn-sm btn-outline-primary copy-code-btn" data-vuln-id="${vulnId}" style="margin-left: auto;">
                                                📋 Copy Code
                                            </button>
                                        </div>
                                        <pre><code class="secure-code"></code></pre>
                                    </div>
                                </div>
                                <div class="fix-explanation">
                                    <h5>📝 Explanation</h5>
                                    <p class="fix-explanation-text"></p>
                                </div>
                                <div class="fix-metadata">
                                    <span class="confidence-badge"></span>
                                    <span class="fix-type-badge"></span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    attachVulnerabilityEventListeners() {
        const headers = document.querySelectorAll('.vulnerability-header');
        headers.forEach(header => {
            header.addEventListener('click', () => {
                const targetId = header.getAttribute('data-target');
                const details = document.getElementById(targetId);
                const arrow = header.querySelector('.expand-arrow');
                
                if (details.classList.contains('expanded')) {
                    details.classList.remove('expanded');
                    arrow.classList.remove('expanded');
                } else {
                    details.classList.add('expanded');
                    arrow.classList.add('expanded');
                }
            });
        });

        // Add auto-fix button event listeners
        const autoFixButtons = document.querySelectorAll('.auto-fix-btn');
        autoFixButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const vulnId = button.getAttribute('data-vuln-id');
                this.generateAutoFix(vulnId, button);
            });
        });

        // Add copy button event listeners
        const copyButtons = document.querySelectorAll('.copy-code-btn');
        copyButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const vulnId = button.getAttribute('data-vuln-id');
                this.copySecureCode(vulnId, button);
            });
        });

    }

    showLoading(show) {
        this.loading.style.display = show ? 'block' : 'none';
        if (show) {
            this.resultsContainer.innerHTML = '';
        }
    }

    showError(message) {
        this.resultsContainer.innerHTML = `
            <div style="background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; padding: 20px; color: #721c24;">
                <strong>Error:</strong> ${message}
            </div>
        `;
    }

    clearCode() {
        // Cancel any pending real-time analysis
        if (this.analysisDebounceTimer) {
            clearTimeout(this.analysisDebounceTimer);
            this.analysisDebounceTimer = null;
        }
        
        this.editor.setValue('');
        this.clearMarkers();
        this.updateAnalysisStatus('idle', '');
        this.resultsContainer.innerHTML = `
            <div class="placeholder">
                <p>No analysis results yet. Submit some code to get started!</p>
            </div>
        `;
        this.editor.focus();
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    formatVulnerabilityDescription(text) {
        if (!text) return '';
        
        // Escape HTML first
        let formatted = this.escapeHtml(text);
        
        // Convert **bold** to <strong>bold</strong>
        formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Convert *italic* to <em>italic</em>
        formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
        
        // Add section headers for common patterns
        formatted = formatted.replace(/To address this vulnerability, follow these steps:/gi, '<h3>🔧 Recommended Actions</h3>');
        formatted = formatted.replace(/The provided.*?vulnerability\./gi, '<h3>🚨 Security Issue</h3>$&');
        formatted = formatted.replace(/poses significant risks for several reasons:/gi, '<h4>⚠️ Risks</h4>');
        
        // Fix recommendations spacing - add line break after introductory text
        formatted = formatted.replace(/(To remediate this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To address this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To fix this issue, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To resolve this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To fix this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To solve this issue, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To prevent this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        formatted = formatted.replace(/(To mitigate this vulnerability, follow these steps:)\s*(\d+\.)/gi, '$1<br><br>$2');
        
        // Break up long paragraphs into smaller, more readable sections
        formatted = this.breakUpLongParagraphs(formatted);
        
        // Convert bullet points (lines starting with * or -)
        formatted = formatted.replace(/^[\s]*[\*\-]\s+(.+)$/gm, '<li>$1</li>');
        
        // Convert numbered lists (lines starting with numbers)
        formatted = formatted.replace(/^[\s]*\d+\.\s+(.+)$/gm, '<li>$1</li>');
        
        // Wrap consecutive <li> elements in <ul> or <ol>
        formatted = formatted.replace(/(<li>.*<\/li>)/gs, (match) => {
            // Check if it's a numbered list by looking for "1." pattern
            const isNumbered = /\d+\./.test(match);
            const listType = isNumbered ? 'ol' : 'ul';
            return `<${listType}>${match}</${listType}>`;
        });
        
        // Convert line breaks to paragraphs
        formatted = formatted.replace(/\n\n/g, '</p><p>');
        formatted = '<p>' + formatted + '</p>';
        
        // Clean up empty paragraphs
        formatted = formatted.replace(/<p><\/p>/g, '');
        formatted = formatted.replace(/<p>\s*<\/p>/g, '');
        
        return formatted;
    }

    breakUpLongParagraphs(text) {
        // Split long sentences and create better paragraph breaks
        let formatted = text;
        
        // Break up sentences that are too long (more than 150 characters)
        formatted = formatted.replace(/([.!?])\s+([A-Z][^.!?]{100,})/g, '$1</p><p>$2');
        
        // Add breaks after common transition phrases
        formatted = formatted.replace(/(\.)\s+(However,|Additionally,|Furthermore,|Moreover,|In addition,|For example,|Specifically,|In particular,|This means|This approach|This method|This technique)/gi, '$1</p><p>$2');
        
        // Break up lists that are embedded in paragraphs
        formatted = formatted.replace(/([.!?])\s+(\d+\.\s+)/g, '$1</p><p>$2');
        formatted = formatted.replace(/([.!?])\s+([\*\-]\s+)/g, '$1</p><p>$2');
        
        // Break up risk explanations
        formatted = formatted.replace(/([.!?])\s+(Hardcoding credentials|This vulnerability|The risk|The exposure|The threat)/gi, '$1</p><p>$2');
        
        // Break up solution explanations  
        formatted = formatted.replace(/([.!?])\s+(To fix|To resolve|To address|The solution|The fix|The remedy)/gi, '$1</p><p>$2');
        
        return formatted;
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.selectedFile = file;
            this.fileNameDisplay.textContent = file.name;
            this.analyzeFileBtn.style.display = 'inline-block';
        }
    }

    async analyzeFile() {
        if (!this.selectedFile) {
            this.showError('Please select a file first.');
            return;
        }

        this.showLoading(true);
        this.analyzeFileBtn.disabled = true;
        this.uploadBtn.disabled = true;

        try {
            const formData = new FormData();
            formData.append('file', this.selectedFile);
            
            // Include project_id if available
            if (this.projectId) {
                formData.append('project_id', this.projectId);
            }

            const response = await fetch('/api/analyze-file', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            
            if (result.files) {
                this.displayMultiFileResults(result);
            } else {
                this.displayResults(result);
            }
        } catch (error) {
            console.error('File analysis failed:', error);
            this.showError('File analysis failed. Please check your file and try again.');
        } finally {
            this.showLoading(false);
            this.analyzeFileBtn.disabled = false;
            this.uploadBtn.disabled = false;
        }
    }

    displayMultiFileResults(result) {
        if (result.error) {
            this.showError(result.error);
            return;
        }

        const files = result.files || [];
        // Cache latest analyzed files for auto-fix context lookup
        this.latestAnalyzedFiles = files;
        const summary = result.summary || {};

        let html = '';

        // Overall summary
        html += `
            <div class="analysis-summary">
                <h3>📊 Project Analysis Summary</h3>
                <div class="summary-stats">
                    <div class="stat-item">
                        <span class="stat-number">${summary.total_files || 0}</span>
                        <span class="stat-label">Files Analyzed</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">${summary.files_with_issues || 0}</span>
                        <span class="stat-label">Files with Issues</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" style="color: #ff4757;">${summary.high || 0}</span>
                        <span class="stat-label">High</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" style="color: #ffa726;">${summary.medium || 0}</span>
                        <span class="stat-label">Medium</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" style="color: #66bb6a;">${summary.low || 0}</span>
                        <span class="stat-label">Low</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">${summary.total_issues || 0}</span>
                        <span class="stat-label">Total Issues</span>
                    </div>
                </div>
            </div>
        `;

        if (result.warning) {
            html += `
                <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px; padding: 15px; color: #856404; margin: 20px 0;">
                    <strong>⚠️ Warning:</strong> ${result.warning}
                </div>
            `;
        }

        // Display results for each file
        if (files.length > 0) {
                    files.forEach((fileData, index) => {
                const analysis = fileData.analysis;
                const vulnerabilities = analysis.vulnerabilities || [];
                const fileSummary = analysis.summary || {};

                html += `
                    <div class="file-result">
                        <div class="file-header">
                            <h4>📄 ${this.escapeHtml(fileData.filename)}</h4>
                            <span class="file-stats">
                                ${fileSummary.total_issues > 0 ? 
                                    `<span style="color: #ff4757;">${fileSummary.total_issues} issue(s)</span>` : 
                                    '<span style="color: #28a745;">✓ No issues</span>'}
                            </span>
                        </div>
                        <div class="file-vulnerabilities" data-file-index="${index}">
                `;

                if (vulnerabilities.length > 0) {
                    html += vulnerabilities.map(vuln => this.createVulnerabilityHTML(vuln)).join('');
                } else {
                    html += '<p style="color: #28a745; padding: 20px; margin: 0;">✓ No security issues found in this file</p>';
                }

                html += '</div></div>';
            });
        } else if (summary.total_issues === 0) {
            html += `
                <div style="text-align: center; color: #28a745; padding: 40px;">
                    <h3>✅ No Security Issues Found!</h3>
                    <p>All analyzed files appear to be free from common security vulnerabilities.</p>
                </div>
            `;
        }

        this.resultsContainer.innerHTML = html;
        this.attachVulnerabilityEventListeners();
    }

    async generateAutoFix(vulnId, button) {
        // Generate auto-fix for a vulnerability
        
        // Find the vulnerability data
        const vulnerabilityElement = document.getElementById(vulnId);
        if (!vulnerabilityElement) return;
        
        // Get vulnerability data from the DOM
        const vulnerability = this.extractVulnerabilityData(vulnerabilityElement);
        console.log('Extracted vulnerability data:', vulnerability);
        
        if (!vulnerability) {
            console.error('Failed to extract vulnerability data');
            return;
        }
        
        // Show loading state
        const fixResult = document.getElementById(`fix-${vulnId}`);
        const fixLoading = fixResult.querySelector('.fix-loading');
        const fixContent = fixResult.querySelector('.fix-content');
        
        fixResult.style.display = 'block';
        fixLoading.style.display = 'block';
        fixContent.style.display = 'none';
        button.disabled = true;
        button.textContent = '🔄 Generating...';
        
        try {
            // Get current code from editor
            let code = this.editor.getValue();
            const language = this.languageSelect.value;
            
            // If editor is empty and we analyzed a file, use that file's code context
            if (!code.trim() && typeof vulnerability.file_index === 'number' && this.latestAnalyzedFiles && this.latestAnalyzedFiles[vulnerability.file_index]) {
                const fileObj = this.latestAnalyzedFiles[vulnerability.file_index];
                if (fileObj && fileObj.code) {
                    code = fileObj.code;
                }
            }

            // Prepare request data
            const requestData = {
                vulnerability: vulnerability,
                code: code,
                language: language
            };
            
            console.log('Sending auto-fix request:', requestData);
            
            // Call auto-fix API
            const response = await fetch('/api/generate-fix', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
                console.error('Auto-fix API error:', errorData);
                throw new Error(`HTTP error! status: ${response.status} - ${errorData.error || 'Unknown error'}`);
            }
            
            const fixData = await response.json();
            
            // Debug: Log the response
            console.log('Auto-fix response:', fixData);
            
            // Display the fix
            this.displayAutoFix(fixData, vulnId);
            
        } catch (error) {
            console.error('Auto-fix generation failed:', error);
            this.showAutoFixError(vulnId, 'Failed to generate auto-fix. Please try again.');
        } finally {
            fixLoading.style.display = 'none';
            button.disabled = false;
            button.textContent = '🔧 Generate Auto-Fix';
        }
    }

    extractVulnerabilityData(vulnerabilityElement) {
        // Extract vulnerability data from DOM element
        
        const description = vulnerabilityElement.querySelector('.vulnerability-description');
        const codeSnippet = vulnerabilityElement.querySelector('.code-snippet code');
        const suggestion = vulnerabilityElement.querySelector('.suggestion div');
        
        // Find the vulnerability header to get type and severity
        const header = vulnerabilityElement.closest('.vulnerability').querySelector('.vulnerability-header');
        const typeElement = header.querySelector('.vulnerability-title');
        const severityElement = header.querySelector('.severity-badge');
        const lineElement = header.querySelector('.line-number');
        
        const data = {
            type: typeElement ? typeElement.textContent : 'Unknown',
            severity: severityElement ? severityElement.textContent.toLowerCase() : 'medium',
            line: lineElement ? parseInt(lineElement.textContent.replace('Line ', '')) : 0,
            description: description ? description.textContent : '',
            code_snippet: codeSnippet ? codeSnippet.textContent : '',
            suggestion: suggestion ? suggestion.textContent : '',
            owasp_category: ''
        };

        // Attach file index to help fetch correct file code for auto-fix
        const fileContainer = vulnerabilityElement.closest('.file-vulnerabilities');
        if (fileContainer && fileContainer.dataset && typeof fileContainer.dataset.fileIndex !== 'undefined') {
            data.file_index = parseInt(fileContainer.dataset.fileIndex);
        }

        // If editor is empty and we have multi-file cache, provide file code context
        const editorCode = this.editor.getValue().trim();
        if (!editorCode && typeof data.file_index === 'number' && this.latestAnalyzedFiles && this.latestAnalyzedFiles[data.file_index]) {
            const fileObj = this.latestAnalyzedFiles[data.file_index];
            if (fileObj && fileObj.code) {
                data.file_code_context = fileObj.code;
            }
        }

        return data;
    }

    displayAutoFix(fixData, vulnId) {
        // Display the generated auto-fix
        
        const fixResult = document.getElementById(`fix-${vulnId}`);
        const fixContent = fixResult.querySelector('.fix-content');
        
        // Update vulnerable code
        const vulnerableCode = fixContent.querySelector('.vulnerable-code');
        const originalCode = fixData.original_code || fixData.code_snippet || this.getVulnerableCodeFromVuln(vulnId);
        vulnerableCode.textContent = originalCode || 'Vulnerable code not available';
        
        // Update secure code
        const secureCode = fixContent.querySelector('.secure-code');
        secureCode.textContent = fixData.secure_code || 'No secure code generated';
        
        // Update explanation
        const explanationText = fixContent.querySelector('.fix-explanation-text');
        explanationText.textContent = fixData.explanation || 'No explanation provided';
        
        // Update metadata badges
        const confidenceBadge = fixContent.querySelector('.confidence-badge');
        const fixTypeBadge = fixContent.querySelector('.fix-type-badge');
        
        confidenceBadge.textContent = `Confidence: ${fixData.confidence || 0}/10`;
        confidenceBadge.className = `confidence-badge ${this.getConfidenceClass(fixData.confidence || 0)}`;
        
        fixTypeBadge.textContent = `Type: ${fixData.fix_type || 'unknown'}`;
        fixTypeBadge.className = `fix-type-badge ${this.getFixTypeClass(fixData.fix_type || 'unknown')}`;
        
        // Show the content
        fixContent.style.display = 'block';
    }

    getConfidenceClass(confidence) {
        if (confidence >= 8) return 'high-confidence';
        if (confidence >= 5) return 'medium-confidence';
        return 'low-confidence';
    }

    getFixTypeClass(fixType) {
        const typeMap = {
            'parameterized_query': 'fix-param',
            'input_validation': 'fix-validation',
            'secure_library': 'fix-library',
            'ai_generated': 'fix-ai',
            'manual': 'fix-manual'
        };
        return typeMap[fixType] || 'fix-unknown';
    }

    showAutoFixError(vulnId, message) {
        // Show error message for auto-fix generation
        
        const fixResult = document.getElementById(`fix-${vulnId}`);
        const fixContent = fixResult.querySelector('.fix-content');
        
        fixContent.innerHTML = `
            <div style="color: #dc3545; text-align: center; padding: 20px;">
                <h4>❌ Auto-Fix Error</h4>
                <p>${message}</p>
            </div>
        `;
        fixContent.style.display = 'block';
    }

    getVulnerableCodeFromVuln(vulnId) {
        // Try to get the vulnerable code from the vulnerability element
        const vulnerabilityElement = document.getElementById(vulnId);
        if (!vulnerabilityElement) return '';
        
        const codeSnippet = vulnerabilityElement.querySelector('.code-snippet code');
        return codeSnippet ? codeSnippet.textContent : '';
    }

    async copySecureCode(vulnId, button) {
        // Copy the secure code to clipboard
        try {
            const fixResult = document.getElementById(`fix-${vulnId}`);
            const secureCodeElement = fixResult.querySelector('.secure-code');
            
            if (!secureCodeElement || !secureCodeElement.textContent.trim()) {
                alert('No secure code available to copy');
                return;
            }
            
            const codeToCopy = secureCodeElement.textContent;
            
            // Use the modern clipboard API if available
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(codeToCopy);
            } else {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = codeToCopy;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                textArea.style.top = '-999999px';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }
            
            // Show success feedback
            const originalText = button.textContent;
            button.textContent = '✅ Copied!';
            button.style.background = '#28a745';
            button.style.color = 'white';
            
            // Reset button after 2 seconds
            setTimeout(() => {
                button.textContent = originalText;
                button.style.background = '';
                button.style.color = '';
            }, 2000);
            
        } catch (error) {
            console.error('Failed to copy code:', error);
            alert('Failed to copy code to clipboard');
        }
    }

}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecureCodingAssistant();
});

// Add some sample code for testing
window.addSampleCode = (type) => {
    const codeInput = document.getElementById('code-input');
    const languageSelect = document.getElementById('language-select');
    
    const samples = {
        python_sql: `import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query - susceptible to SQL injection
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

# Example usage
user_data = get_user_data(request.args.get('id'))`,

        javascript_xss: `function displayUserComment(comment) {
    // Vulnerable to XSS - directly inserting user input into DOM
    document.getElementById('comments').innerHTML += 
        '<div class="comment">' + comment + '</div>';
}

// Hardcoded API key - security risk
const API_KEY = 'sk-1234567890abcdef';

function processUserInput() {
    const userInput = document.getElementById('userInput').value;
    
    // No input validation
    displayUserComment(userInput);
    
    // Insecure eval usage
    if (userInput.startsWith('calc:')) {
        const result = eval(userInput.substring(5));
        alert('Result: ' + result);
    }
}`
    };

    if (samples[type]) {
        codeInput.value = samples[type];
        if (type.startsWith('python')) {
            languageSelect.value = 'python';
        } else if (type.startsWith('javascript')) {
            languageSelect.value = 'javascript';
        }
        
        // Trigger auto-resize
        codeInput.style.height = 'auto';
        codeInput.style.height = Math.max(400, codeInput.scrollHeight) + 'px';
    }
};