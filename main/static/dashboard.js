// Dashboard JavaScript for Project Management
class Dashboard {
    constructor() {
        this.projects = [];
        this.filteredProjects = [];
        this.searchQuery = '';
        this.sortBy = 'updated';
        this.initializeElements();
        this.attachEventListeners();
        this.loadProjects();
    }

    initializeElements() {
        this.projectsContainer = document.getElementById('projects-container');
        this.createProjectBtn = document.getElementById('create-project-btn');
        this.createProjectModal = document.getElementById('create-project-modal');
        this.projectNameInput = document.getElementById('project-name');
        this.projectDescriptionInput = document.getElementById('project-description');
        this.confirmCreateBtn = document.getElementById('confirm-create-btn');
        this.cancelCreateBtn = document.getElementById('cancel-create-btn');
        this.searchInput = document.getElementById('search-input');
        this.clearSearchBtn = document.getElementById('clear-search-btn');
        this.sortSelect = document.getElementById('sort-select');
    }

    attachEventListeners() {
        this.createProjectBtn.addEventListener('click', () => this.openCreateModal());
        this.confirmCreateBtn.addEventListener('click', () => this.createProject());
        this.cancelCreateBtn.addEventListener('click', () => this.closeCreateModal());
        
        // Search functionality
        this.searchInput.addEventListener('input', (e) => this.handleSearch(e.target.value));
        this.clearSearchBtn.addEventListener('click', () => this.clearSearch());
        
        // Sort functionality
        this.sortSelect.addEventListener('change', (e) => {
            this.sortBy = e.target.value;
            this.applyFiltersAndSort();
        });
        
        // Close modal when clicking outside
        this.createProjectModal.addEventListener('click', (e) => {
            if (e.target === this.createProjectModal) {
                this.closeCreateModal();
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+K or Cmd+K to focus search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.searchInput.focus();
            }
            
            // Escape to close modal
            if (e.key === 'Escape' && this.createProjectModal.style.display === 'block') {
                this.closeCreateModal();
            }
            
            // Escape to clear search when search is focused
            if (e.key === 'Escape' && document.activeElement === this.searchInput) {
                this.clearSearch();
            }
        });
    }

    async loadProjects() {
        try {
            const response = await fetch('/api/projects');
            if (!response.ok) {
                throw new Error('Failed to load projects');
            }
            this.projects = await response.json();
            this.applyFiltersAndSort();
        } catch (error) {
            console.error('Error loading projects:', error);
            this.showError('Failed to load projects. Please refresh the page.');
        }
    }

    handleSearch(query) {
        this.searchQuery = query.toLowerCase().trim();
        this.clearSearchBtn.style.display = this.searchQuery ? 'block' : 'none';
        this.applyFiltersAndSort();
    }

    clearSearch() {
        this.searchInput.value = '';
        this.searchQuery = '';
        this.clearSearchBtn.style.display = 'none';
        this.applyFiltersAndSort();
    }

    applyFiltersAndSort() {
        // Filter projects
        this.filteredProjects = this.projects.filter(project => {
            if (!this.searchQuery) return true;
            const name = (project.name || '').toLowerCase();
            const description = (project.description || '').toLowerCase();
            return name.includes(this.searchQuery) || description.includes(this.searchQuery);
        });

        // Sort projects
        this.filteredProjects.sort((a, b) => {
            switch (this.sortBy) {
                case 'name':
                    return (a.name || '').localeCompare(b.name || '');
                case 'name-desc':
                    return (b.name || '').localeCompare(a.name || '');
                case 'created':
                    return new Date(b.created_at) - new Date(a.created_at);
                case 'favorites':
                    if (a.is_favorite && !b.is_favorite) return -1;
                    if (!a.is_favorite && b.is_favorite) return 1;
                    return new Date(b.updated_at) - new Date(a.updated_at);
                case 'updated':
                default:
                    return new Date(b.updated_at) - new Date(a.updated_at);
            }
        });

        this.renderProjects();
    }

    renderProjects() {
        if (this.projects.length === 0) {
            this.projectsContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📁</div>
                    <h3>No Projects Yet</h3>
                    <p>Create your first project to start analyzing code security</p>
                </div>
            `;
            return;
        }

        if (this.filteredProjects.length === 0) {
            this.projectsContainer.innerHTML = `
                <div class="no-results">
                    <div class="no-results-icon">🔍</div>
                    <h3>No Projects Found</h3>
                    <p>No projects match your search "${this.escapeHtml(this.searchQuery)}"</p>
                </div>
            `;
            return;
        }

        const projectsHTML = this.filteredProjects.map(project => this.createProjectCardHTML(project)).join('');
        this.projectsContainer.innerHTML = `
            <div class="projects-grid">
                ${projectsHTML}
            </div>
        `;

        // Attach event listeners to project cards
        this.attachProjectCardListeners();
    }

    createProjectCardHTML(project) {
        const createdDate = new Date(project.created_at).toLocaleDateString();
        const updatedDate = new Date(project.updated_at).toLocaleDateString();
        const isFavorite = project.is_favorite || false;
        
        // Calculate stats from analysis history
        const stats = this.calculateProjectStats(project);
        
        return `
            <div class="project-card" data-project-id="${project.id}">
                <div class="project-card-header">
                    <h3 class="project-card-title">${this.escapeHtml(project.name)}</h3>
                    <div class="project-card-actions">
                        <button class="favorite-btn ${isFavorite ? 'favorited' : ''}" data-project-id="${project.id}" title="${isFavorite ? 'Remove from favorites' : 'Add to favorites'}">
                            ${isFavorite ? '⭐' : '☆'}
                        </button>
                        <button class="project-card-btn delete-btn" data-project-id="${project.id}" title="Delete project">
                            🗑️
                        </button>
                    </div>
                </div>
                ${project.description ? `<p style="color: #6c757d; margin-bottom: 15px;">${this.escapeHtml(project.description)}</p>` : ''}
                <div class="project-card-meta">
                    <div>Created: ${createdDate}</div>
                    <div>Updated: ${updatedDate}</div>
                </div>
                ${stats.totalIssues > 0 ? `
                    <div class="project-card-stats">
                        <div class="project-stat">
                            <span class="project-stat-number stat-high">${stats.high}</span>
                            <span class="project-stat-label">High</span>
                        </div>
                        <div class="project-stat">
                            <span class="project-stat-number stat-medium">${stats.medium}</span>
                            <span class="project-stat-label">Medium</span>
                        </div>
                        <div class="project-stat">
                            <span class="project-stat-number stat-low">${stats.low}</span>
                            <span class="project-stat-label">Low</span>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    calculateProjectStats(project) {
        // Calculate stats from the latest analysis if available
        if (project.latest_analysis) {
            const summary = project.latest_analysis.summary || {};
            return {
                high: summary.high || 0,
                medium: summary.medium || 0,
                low: summary.low || 0,
                totalIssues: summary.total_issues || 0
            };
        }
        return { high: 0, medium: 0, low: 0, totalIssues: 0 };
    }

    attachProjectCardListeners() {
        // Project card click to open project
        document.querySelectorAll('.project-card').forEach(card => {
            card.addEventListener('click', (e) => {
                // Don't trigger if clicking on action buttons
                if (e.target.closest('.delete-btn') || e.target.closest('.favorite-btn')) {
                    return;
                }
                const projectId = card.getAttribute('data-project-id');
                window.location.href = `/project/${projectId}`;
            });
        });

        // Favorite button click
        document.querySelectorAll('.favorite-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const projectId = btn.getAttribute('data-project-id');
                await this.toggleFavorite(projectId, btn);
            });
        });

        // Delete button click
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const projectId = btn.getAttribute('data-project-id');
                if (confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
                    await this.deleteProject(projectId);
                }
            });
        });
    }

    async toggleFavorite(projectId, buttonElement) {
        try {
            const project = this.projects.find(p => p.id === projectId);
            if (!project) return;

            const newFavoriteState = !(project.is_favorite || false);

            const response = await fetch(`/api/projects/${projectId}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    is_favorite: newFavoriteState
                })
            });

            if (!response.ok) {
                throw new Error('Failed to update favorite');
            }

            // Update local project data
            project.is_favorite = newFavoriteState;
            
            // Update button appearance
            if (newFavoriteState) {
                buttonElement.classList.add('favorited');
                buttonElement.textContent = '⭐';
                buttonElement.title = 'Remove from favorites';
            } else {
                buttonElement.classList.remove('favorited');
                buttonElement.textContent = '☆';
                buttonElement.title = 'Add to favorites';
            }

            // Re-apply filters and sort if sorting by favorites
            if (this.sortBy === 'favorites') {
                this.applyFiltersAndSort();
            }
        } catch (error) {
            console.error('Error toggling favorite:', error);
            alert('Failed to update favorite. Please try again.');
        }
    }

    openCreateModal() {
        this.createProjectModal.style.display = 'block';
        this.projectNameInput.value = '';
        this.projectDescriptionInput.value = '';
        this.projectNameInput.focus();
    }

    closeCreateModal() {
        this.createProjectModal.style.display = 'none';
    }

    async createProject() {
        const name = this.projectNameInput.value.trim();
        const description = this.projectDescriptionInput.value.trim();

        if (!name) {
            alert('Please enter a project name');
            return;
        }

        this.confirmCreateBtn.disabled = true;
        this.confirmCreateBtn.textContent = 'Creating...';

        try {
            const response = await fetch('/api/projects', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    description: description
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to create project');
            }

            const project = await response.json();
            this.closeCreateModal();
            await this.loadProjects();
        } catch (error) {
            console.error('Error creating project:', error);
            alert('Failed to create project: ' + error.message);
        } finally {
            this.confirmCreateBtn.disabled = false;
            this.confirmCreateBtn.textContent = 'Create Project';
        }
    }

    async deleteProject(projectId) {
        try {
            const response = await fetch(`/api/projects/${projectId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error('Failed to delete project');
            }

            await this.loadProjects();
        } catch (error) {
            console.error('Error deleting project:', error);
            alert('Failed to delete project: ' + error.message);
        }
    }

    showError(message) {
        this.projectsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">⚠️</div>
                <h3>Error</h3>
                <p>${this.escapeHtml(message)}</p>
                <button class="btn btn-primary" onclick="location.reload()">Reload Page</button>
            </div>
        `;
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
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new Dashboard();
});

