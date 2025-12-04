"""
Automatic updater for GEEKS-AD-Tools
Handles downloading, installing, and rolling back updates from GitHub
"""
import os
import shutil
import subprocess
import requests
import zipfile
import tarfile
import json
import logging
from datetime import datetime
from pathlib import Path
import tempfile

logger = logging.getLogger(__name__)

class Updater:
    def __init__(self, repo=None, branch=None, base_path=None):
        """
        Initialize the updater
        
        Args:
            repo: GitHub repository (owner/repo)
            branch: Branch to update from (default: stable)
            base_path: Base installation path
        """
        self.repo = repo or self._get_github_repo()
        self.branch = branch or self._get_github_branch()
        self.base_path = base_path or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.backup_path = os.path.join(self.base_path, 'backups')
        self.temp_path = os.path.join(tempfile.gettempdir(), 'geeks_ad_update')
        
        # Ensure backup directory exists
        os.makedirs(self.backup_path, exist_ok=True)
        os.makedirs(self.temp_path, exist_ok=True)
    
    def _get_github_repo(self):
        """Get GitHub repo from config"""
        try:
            config_path = os.path.join(self.base_path, 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get('github_repo', 'GeeksTechnologies/GEEKS-AD-Tools')
        except:
            pass
        return os.environ.get('GITHUB_REPO', 'GeeksTechnologies/GEEKS-AD-Tools')
    
    def _get_github_branch(self):
        """Get GitHub branch from config"""
        try:
            config_path = os.path.join(self.base_path, 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get('github_branch', 'stable')
        except:
            pass
        return os.environ.get('GITHUB_BRANCH', 'stable')
    
    def check_update_available(self):
        """
        Check if an update is available
        
        Returns:
            dict with update information or None
        """
        try:
            from .version_checker import check_github_version
            version_data = check_github_version(force_refresh=True)
            
            if version_data.get('update_available'):
                return {
                    'available': True,
                    'current_version': version_data['current_version'],
                    'latest_version': version_data['latest_version'],
                    'release_url': version_data['release_url'],
                    'release_notes': version_data.get('release_notes'),
                    'changelog': version_data.get('changelog')
                }
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
        
        return {'available': False}
    
    def create_backup(self):
        """
        Create a backup of the current installation
        
        Returns:
            str: Path to backup directory, or None if failed
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = os.path.join(self.backup_path, f'backup_{timestamp}')
            os.makedirs(backup_dir, exist_ok=True)
            
            # Files/directories to backup
            items_to_backup = [
                'app',
                'config.json',
                'requirements.txt',
                'app.py',
                'database.db'  # If exists
            ]
            
            logger.info(f"Creating backup in {backup_dir}")
            
            for item in items_to_backup:
                source = os.path.join(self.base_path, item)
                if os.path.exists(source):
                    dest = os.path.join(backup_dir, item)
                    if os.path.isdir(source):
                        shutil.copytree(source, dest, dirs_exist_ok=True)
                    else:
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.copy2(source, dest)
                    logger.info(f"Backed up {item}")
            
            # Save backup metadata
            metadata = {
                'timestamp': timestamp,
                'backup_path': backup_dir,
                'base_path': self.base_path,
                'items_backed_up': items_to_backup
            }
            
            with open(os.path.join(backup_dir, 'backup_metadata.json'), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Backup created successfully: {backup_dir}")
            return backup_dir
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None
    
    def download_release(self, version=None):
        """
        Download the latest release or specific version from GitHub
        
        Args:
            version: Specific version to download (None for latest)
            
        Returns:
            str: Path to downloaded archive, or None if failed
        """
        try:
            if version:
                # Download specific release
                release_url = f"https://api.github.com/repos/{self.repo}/releases/tags/v{version}"
            else:
                # Download latest release
                release_url = f"https://api.github.com/repos/{self.repo}/releases/latest"
            
            logger.info(f"Fetching release info from {release_url}")
            response = requests.get(release_url, timeout=30)
            
            if response.status_code != 200:
                # Try downloading from branch as zip
                return self._download_from_branch()
            
            release_data = response.json()
            assets = release_data.get('assets', [])
            
            # Look for zip or tar.gz asset
            download_url = None
            filename = None
            
            for asset in assets:
                name = asset.get('name', '')
                if name.endswith('.zip') or name.endswith('.tar.gz'):
                    download_url = asset.get('browser_download_url')
                    filename = name
                    break
            
            if not download_url:
                # No release assets, try downloading from branch
                return self._download_from_branch()
            
            # Download the file
            logger.info(f"Downloading {filename} from {download_url}")
            download_path = os.path.join(self.temp_path, filename)
            
            response = requests.get(download_url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Downloaded to {download_path}")
            return download_path
            
        except Exception as e:
            logger.error(f"Error downloading release: {e}")
            # Fallback to branch download
            return self._download_from_branch()
    
    def _download_from_branch(self):
        """
        Download source code from GitHub branch as zip
        
        Returns:
            str: Path to downloaded archive, or None if failed
        """
        try:
            download_url = f"https://github.com/{self.repo}/archive/refs/heads/{self.branch}.zip"
            filename = f"{self.branch}.zip"
            download_path = os.path.join(self.temp_path, filename)
            
            logger.info(f"Downloading branch {self.branch} from {download_url}")
            
            response = requests.get(download_url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Downloaded branch to {download_path}")
            return download_path
            
        except Exception as e:
            logger.error(f"Error downloading from branch: {e}")
            return None
    
    def extract_archive(self, archive_path, extract_to=None):
        """
        Extract downloaded archive
        
        Args:
            archive_path: Path to archive file
            extract_to: Directory to extract to (default: temp_path)
            
        Returns:
            str: Path to extracted directory, or None if failed
        """
        try:
            if extract_to is None:
                extract_to = os.path.join(self.temp_path, 'extracted')
            
            os.makedirs(extract_to, exist_ok=True)
            
            logger.info(f"Extracting {archive_path} to {extract_to}")
            
            if archive_path.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.endswith('.tar.gz'):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_to)
            else:
                logger.error(f"Unsupported archive format: {archive_path}")
                return None
            
            # Find the actual project directory (might be nested)
            extracted_dirs = [d for d in os.listdir(extract_to) if os.path.isdir(os.path.join(extract_to, d))]
            if extracted_dirs:
                # Usually the first directory is the project
                project_dir = os.path.join(extract_to, extracted_dirs[0])
                if os.path.exists(os.path.join(project_dir, 'app')):
                    return project_dir
            
            return extract_to
            
        except Exception as e:
            logger.error(f"Error extracting archive: {e}")
            return None
    
    def install_update(self, source_dir, backup_dir=None):
        """
        Install the update from extracted source
        
        Args:
            source_dir: Path to extracted source code
            backup_dir: Path to backup (for rollback info)
            
        Returns:
            dict with installation result
        """
        try:
            logger.info(f"Installing update from {source_dir}")
            
            # Files/directories to update
            items_to_update = [
                'app',
                'requirements.txt',
                'app.py'
            ]
            
            # Update each item
            for item in items_to_update:
                source = os.path.join(source_dir, item)
                dest = os.path.join(self.base_path, item)
                
                if not os.path.exists(source):
                    logger.warning(f"Source {source} does not exist, skipping")
                    continue
                
                # Remove old version
                if os.path.exists(dest):
                    if os.path.isdir(dest):
                        shutil.rmtree(dest)
                    else:
                        os.remove(dest)
                
                # Copy new version
                if os.path.isdir(source):
                    shutil.copytree(source, dest)
                else:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(source, dest)
                
                logger.info(f"Updated {item}")
            
            # Save update metadata
            update_metadata = {
                'timestamp': datetime.now().isoformat(),
                'source_dir': source_dir,
                'backup_dir': backup_dir,
                'items_updated': items_to_update
            }
            
            metadata_path = os.path.join(self.base_path, 'update_metadata.json')
            with open(metadata_path, 'w') as f:
                json.dump(update_metadata, f, indent=2)
            
            logger.info("Update installed successfully")
            return {
                'success': True,
                'message': 'Update installed successfully',
                'backup_dir': backup_dir
            }
            
        except Exception as e:
            logger.error(f"Error installing update: {e}")
            return {
                'success': False,
                'message': f'Error installing update: {str(e)}',
                'backup_dir': backup_dir
            }
    
    def rollback(self, backup_dir):
        """
        Rollback to a previous backup
        
        Args:
            backup_dir: Path to backup directory
            
        Returns:
            dict with rollback result
        """
        try:
            if not os.path.exists(backup_dir):
                return {
                    'success': False,
                    'message': 'Backup directory not found'
                }
            
            # Load backup metadata
            metadata_path = os.path.join(backup_dir, 'backup_metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    items_to_restore = metadata.get('items_backed_up', [])
            else:
                # Fallback: restore common items
                items_to_restore = ['app', 'config.json', 'requirements.txt', 'app.py']
            
            logger.info(f"Rolling back from {backup_dir}")
            
            for item in items_to_restore:
                source = os.path.join(backup_dir, item)
                dest = os.path.join(self.base_path, item)
                
                if not os.path.exists(source):
                    continue
                
                # Remove current version
                if os.path.exists(dest):
                    if os.path.isdir(dest):
                        shutil.rmtree(dest)
                    else:
                        os.remove(dest)
                
                # Restore from backup
                if os.path.isdir(source):
                    shutil.copytree(source, dest)
                else:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(source, dest)
                
                logger.info(f"Restored {item}")
            
            logger.info("Rollback completed successfully")
            return {
                'success': True,
                'message': 'Rollback completed successfully'
            }
            
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return {
                'success': False,
                'message': f'Error during rollback: {str(e)}'
            }
    
    def perform_update(self, version=None):
        """
        Perform a complete update: backup, download, extract, install
        
        Args:
            version: Specific version to update to (None for latest)
            
        Returns:
            dict with update result
        """
        try:
            logger.info("Starting update process")
            
            # Step 1: Create backup
            backup_dir = self.create_backup()
            if not backup_dir:
                return {
                    'success': False,
                    'message': 'Failed to create backup',
                    'step': 'backup'
                }
            
            # Step 2: Download update
            archive_path = self.download_release(version)
            if not archive_path:
                return {
                    'success': False,
                    'message': 'Failed to download update',
                    'step': 'download',
                    'backup_dir': backup_dir
                }
            
            # Step 3: Extract archive
            source_dir = self.extract_archive(archive_path)
            if not source_dir:
                return {
                    'success': False,
                    'message': 'Failed to extract update',
                    'step': 'extract',
                    'backup_dir': backup_dir
                }
            
            # Step 4: Install update
            result = self.install_update(source_dir, backup_dir)
            
            # Cleanup temp files
            try:
                if os.path.exists(self.temp_path):
                    shutil.rmtree(self.temp_path)
            except:
                pass
            
            return result
            
        except Exception as e:
            logger.error(f"Error during update: {e}")
            return {
                'success': False,
                'message': f'Update failed: {str(e)}',
                'step': 'unknown'
            }
    
    def get_backup_list(self):
        """
        Get list of available backups
        
        Returns:
            list of backup directories
        """
        try:
            if not os.path.exists(self.backup_path):
                return []
            
            backups = []
            for item in os.listdir(self.backup_path):
                backup_dir = os.path.join(self.backup_path, item)
                if os.path.isdir(backup_dir) and item.startswith('backup_'):
                    metadata_path = os.path.join(backup_dir, 'backup_metadata.json')
                    timestamp = item.replace('backup_', '')
                    
                    if os.path.exists(metadata_path):
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                            timestamp = metadata.get('timestamp', timestamp)
                    
                    backups.append({
                        'path': backup_dir,
                        'timestamp': timestamp,
                        'display': timestamp.replace('_', ' ').replace('-', '/')
                    })
            
            # Sort by timestamp (newest first)
            backups.sort(key=lambda x: x['timestamp'], reverse=True)
            return backups
            
        except Exception as e:
            logger.error(f"Error getting backup list: {e}")
            return []

