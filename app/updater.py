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
            # Note: Database files are NOT backed up - each installation has its own DB
            # Migrations are backed up so we can rollback migration files if needed
            items_to_backup = [
                'app',
                'config.json',
                'requirements.txt',
                'app.py',
                'migrations',  # Backup migrations directory (not the DB, just migration files)
            ]
            
            # Also backup credentials and other important files (but NOT database)
            important_files = [
                '.credentials.enc',
                '.credentials.key'
            ]
            for important_file in important_files:
                file_path = os.path.join(self.base_path, important_file)
                if os.path.exists(file_path):
                    items_to_backup.append(important_file)
            
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
                    self._safe_extract_zip(zip_ref, extract_to)
            elif archive_path.endswith('.tar.gz'):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    self._safe_extract_tar(tar_ref, extract_to)
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

    def _is_safe_archive_target(self, extract_to, member_name):
        """Ensure archive members cannot escape the intended extraction directory."""
        base_dir = os.path.realpath(extract_to)
        target_path = os.path.realpath(os.path.join(extract_to, member_name))
        return os.path.commonpath([base_dir, target_path]) == base_dir

    def _safe_extract_zip(self, zip_ref, extract_to):
        for member in zip_ref.infolist():
            if not self._is_safe_archive_target(extract_to, member.filename):
                raise ValueError(f"Unsafe archive member path: {member.filename}")
            zip_ref.extract(member, extract_to)

    def _safe_extract_tar(self, tar_ref, extract_to):
        for member in tar_ref.getmembers():
            if not self._is_safe_archive_target(extract_to, member.name):
                raise ValueError(f"Unsafe archive member path: {member.name}")
            tar_ref.extract(member, extract_to)
    
    def run_database_migrations(self):
        """
        Run database migrations after update
        
        This applies new migrations to the local database. Each installation
        maintains its own database file, which is not included in updates.
        Migrations are applied to bring the local database schema up to date.
        
        Returns:
            dict with migration result
        """
        try:
            logger.info("Running database migrations...")
            logger.info("Note: This updates the local database schema. Database files are not included in updates.")
            
            # Change to base path for Flask commands
            original_cwd = os.getcwd()
            os.chdir(self.base_path)
            
            try:
                # Set Flask app environment variable
                env = os.environ.copy()
                env['FLASK_APP'] = 'app.py'
                
                # Find the Flask executable (could be in venv)
                flask_cmd = 'flask'
                venv_flask = os.path.join(self.base_path, 'venv', 'bin', 'flask')
                if os.path.exists(venv_flask):
                    flask_cmd = venv_flask
                
                # Run flask db upgrade
                result = subprocess.run(
                    [flask_cmd, 'db', 'upgrade'],
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    env=env,
                    cwd=self.base_path
                )
                
                if result.returncode == 0:
                    logger.info("Database migrations completed successfully")
                    logger.debug(f"Migration output: {result.stdout}")
                    return {
                        'success': True,
                        'message': 'Database migrations completed successfully',
                        'output': result.stdout
                    }
                else:
                    error_msg = result.stderr or result.stdout or 'Unknown migration error'
                    logger.error(f"Database migration failed: {error_msg}")
                    return {
                        'success': False,
                        'message': f'Database migration failed: {error_msg}',
                        'output': result.stdout,
                        'error': result.stderr
                    }
                    
            finally:
                os.chdir(original_cwd)
                
        except subprocess.TimeoutExpired:
            logger.error("Database migration timed out")
            return {
                'success': False,
                'message': 'Database migration timed out (exceeded 5 minutes)'
            }
        except Exception as e:
            logger.error(f"Error running database migrations: {e}")
            return {
                'success': False,
                'message': f'Error running database migrations: {str(e)}'
            }
    
    def cleanup_after_update(self):
        """
        Cleanup temporary files and old data after successful update
        
        Returns:
            dict with cleanup result
        """
        try:
            logger.info("Cleaning up after update...")
            
            cleanup_items = []
            
            # Cleanup temp update directory
            if os.path.exists(self.temp_path):
                try:
                    shutil.rmtree(self.temp_path)
                    cleanup_items.append(f"Removed temp directory: {self.temp_path}")
                    logger.info(f"Cleaned up temp directory: {self.temp_path}")
                except Exception as e:
                    logger.warning(f"Could not remove temp directory: {e}")
            
            # Cleanup old Python cache files (__pycache__)
            for root, dirs, files in os.walk(self.base_path):
                # Skip venv and other important directories
                if 'venv' in root or '.git' in root or 'backups' in root:
                    continue
                    
                if '__pycache__' in dirs:
                    pycache_dir = os.path.join(root, '__pycache__')
                    try:
                        shutil.rmtree(pycache_dir)
                        cleanup_items.append(f"Removed __pycache__: {pycache_dir}")
                    except Exception as e:
                        logger.warning(f"Could not remove __pycache__ {pycache_dir}: {e}")
            
            # Cleanup .pyc files
            for root, dirs, files in os.walk(self.base_path):
                if 'venv' in root or '.git' in root or 'backups' in root:
                    continue
                    
                for file in files:
                    if file.endswith('.pyc'):
                        pyc_file = os.path.join(root, file)
                        try:
                            os.remove(pyc_file)
                            cleanup_items.append(f"Removed .pyc file: {pyc_file}")
                        except Exception as e:
                            logger.warning(f"Could not remove .pyc file {pyc_file}: {e}")
            
            logger.info(f"Cleanup completed. Removed {len(cleanup_items)} items")
            return {
                'success': True,
                'message': f'Cleanup completed successfully',
                'items_cleaned': cleanup_items
            }
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return {
                'success': False,
                'message': f'Error during cleanup: {str(e)}'
            }
    
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
            # Note: Database files are NOT updated - each installation maintains its own DB
            # Migrations are updated so new migrations can be run
            items_to_update = [
                'app',
                'requirements.txt',
                'app.py',
                'migrations'  # Include migrations directory (migration files, not DB)
            ]
            
            # Do NOT update database files - each installation has its own
            # The database will be migrated using the new migration files
            
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
            
            # Step 1: Run database migrations
            migration_result = self.run_database_migrations()
            if not migration_result.get('success'):
                logger.error(f"Migration failed: {migration_result.get('message')}")
                return {
                    'success': False,
                    'message': f'Update installed but database migration failed: {migration_result.get("message")}',
                    'backup_dir': backup_dir,
                    'migration_error': migration_result.get('message'),
                    'step': 'migration'
                }
            
            # Step 2: Cleanup temporary files
            cleanup_result = self.cleanup_after_update()
            if not cleanup_result.get('success'):
                logger.warning(f"Cleanup had issues: {cleanup_result.get('message')}")
                # Don't fail the update if cleanup fails, just log it
            
            # Save update metadata
            update_metadata = {
                'timestamp': datetime.now().isoformat(),
                'source_dir': source_dir,
                'backup_dir': backup_dir,
                'items_updated': items_to_update,
                'migration_success': migration_result.get('success'),
                'migration_output': migration_result.get('output', ''),
                'cleanup_success': cleanup_result.get('success')
            }
            
            metadata_path = os.path.join(self.base_path, 'update_metadata.json')
            with open(metadata_path, 'w') as f:
                json.dump(update_metadata, f, indent=2)
            
            logger.info("Update installed successfully")
            return {
                'success': True,
                'message': 'Update installed and database migrations completed successfully',
                'backup_dir': backup_dir,
                'migration_result': migration_result,
                'cleanup_result': cleanup_result
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
                # Note: Database files are NOT restored - each installation maintains its own DB
                items_to_restore = ['app', 'config.json', 'requirements.txt', 'app.py', 'migrations']
            
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
            
            # After rollback, we may need to rollback database migrations too
            # This is tricky - we'd need to know which migration to rollback to
            # For now, we'll just log a warning
            logger.warning("Rollback completed. Note: Database migrations were not automatically rolled back.")
            logger.warning("If you need to rollback database changes, you may need to manually run: flask db downgrade")
            
            logger.info("Rollback completed successfully")
            return {
                'success': True,
                'message': 'Rollback completed successfully. Note: Database migrations may need manual rollback.',
                'migration_note': 'Database migrations were not automatically rolled back. Run "flask db downgrade" if needed.'
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
            
            # Step 4: Install update (includes migrations and cleanup)
            result = self.install_update(source_dir, backup_dir)
            
            # If update failed at migration step, offer rollback option
            if not result.get('success') and result.get('step') == 'migration':
                logger.warning("Update failed during migration. Backup is available for rollback.")
                result['rollback_available'] = True
                result['rollback_message'] = 'Update installed but database migration failed. You may need to rollback or manually fix the database.'
            
            # Final cleanup of temp files (if not already done)
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

