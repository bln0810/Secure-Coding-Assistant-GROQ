"""Project Manager for storing and managing analysis projects"""
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional

class ProjectManager:
    """Manages project storage and retrieval"""
    
    def __init__(self, projects_dir: str = None):
        if projects_dir is None:
            projects_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'projects')
        self.projects_dir = projects_dir
        os.makedirs(self.projects_dir, exist_ok=True)
    
    def _get_project_path(self, project_id: str) -> str:
        """Get the file path for a project"""
        return os.path.join(self.projects_dir, f"{project_id}.json")
    
    def create_project(self, name: str, description: str = "") -> Dict:
        """Create a new project"""
        project_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        
        project = {
            'id': project_id,
            'name': name,
            'description': description,
            'created_at': now,
            'updated_at': now,
            'analyses': [],
            'latest_analysis': None,
            'is_favorite': False
        }
        
        self._save_project(project)
        return project
    
    def get_project(self, project_id: str) -> Optional[Dict]:
        """Get a project by ID"""
        project_path = self._get_project_path(project_id)
        if not os.path.exists(project_path):
            return None
        
        try:
            with open(project_path, 'r', encoding='utf-8') as f:
                project = json.load(f)
                # Ensure backward compatibility - add is_favorite if missing
                if 'is_favorite' not in project:
                    project['is_favorite'] = False
                    self._save_project(project)
                return project
        except Exception as e:
            print(f"Error reading project {project_id}: {e}")
            return None
    
    def get_all_projects(self) -> List[Dict]:
        """Get all projects"""
        projects = []
        
        if not os.path.exists(self.projects_dir):
            return projects
        
        for filename in os.listdir(self.projects_dir):
            if filename.endswith('.json'):
                project_id = filename[:-5]  # Remove .json extension
                project = self.get_project(project_id)
                if project:
                    projects.append(project)
        
        # Sort by updated_at, most recent first
        projects.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
        return projects
    
    def update_project(self, project_id: str, updates: Dict) -> Optional[Dict]:
        """Update a project"""
        project = self.get_project(project_id)
        if not project:
            return None
        
        project.update(updates)
        project['updated_at'] = datetime.utcnow().isoformat()
        self._save_project(project)
        return project
    
    def add_analysis(self, project_id: str, analysis_result: Dict) -> Optional[Dict]:
        """Add an analysis result to a project"""
        project = self.get_project(project_id)
        if not project:
            return None
        
        analysis_entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'result': analysis_result
        }
        
        project['analyses'].append(analysis_entry)
        project['latest_analysis'] = analysis_result
        project['updated_at'] = datetime.utcnow().isoformat()
        
        self._save_project(project)
        return project
    
    def delete_project(self, project_id: str) -> bool:
        """Delete a project"""
        project_path = self._get_project_path(project_id)
        if os.path.exists(project_path):
            try:
                os.remove(project_path)
                return True
            except Exception as e:
                print(f"Error deleting project {project_id}: {e}")
                return False
        return False
    
    def _save_project(self, project: Dict):
        """Save a project to disk"""
        project_path = self._get_project_path(project['id'])
        try:
            with open(project_path, 'w', encoding='utf-8') as f:
                json.dump(project, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving project {project['id']}: {e}")
            raise

