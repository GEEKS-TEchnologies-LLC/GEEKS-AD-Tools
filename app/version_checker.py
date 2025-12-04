"""
GitHub version checker for automatic update notifications
"""
import requests
import json
import time
import re
import os
from datetime import datetime, timedelta
from functools import lru_cache
from .version import __version__ as current_version
import logging

logger = logging.getLogger(__name__)

# Cache for version info (in-memory)
_version_cache = {
    'data': None,
    'timestamp': None,
    'cache_duration': 3600  # 1 hour cache
}

# Default GitHub repository (can be overridden in config)
DEFAULT_GITHUB_REPO = "GeeksTechnologies/GEEKS-AD-Tools"  # Update with actual repo
DEFAULT_BRANCH = "stable"  # or "main", "master", etc.

def get_github_repo_config():
    """Get GitHub repo configuration from config file or environment"""
    import os
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {
                    'repo': config.get('github_repo', DEFAULT_GITHUB_REPO),
                    'branch': config.get('github_branch', DEFAULT_BRANCH)
                }
    except Exception as e:
        logger.warning(f"Could not read GitHub config: {e}")
    
    return {
        'repo': os.environ.get('GITHUB_REPO', DEFAULT_GITHUB_REPO),
        'branch': os.environ.get('GITHUB_BRANCH', DEFAULT_BRANCH)
    }

def get_changelog_for_version(version=None):
    """
    Get changelog entry for a specific version
    
    Args:
        version: Version to get changelog for (None for latest)
        
    Returns:
        str: Changelog entry or None
    """
    try:
        changelog_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'CHANGELOG.md')
        if not os.path.exists(changelog_path):
            return None
        
        with open(changelog_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse changelog to find version entry
        if version:
            # Look for specific version
            pattern = rf'## \[{re.escape(version)}\].*?(?=## \[|\Z)'
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(0).strip()
        else:
            # Get latest version entry
            pattern = r'## \[([^\]]+)\].*?(?=## \[|\Z)'
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(0).strip()
        
        return None
    except Exception as e:
        logger.warning(f"Error reading changelog: {e}")
        return None

def check_github_version(force_refresh=False):
    """
    Check GitHub for the latest version from the stable branch
    
    Args:
        force_refresh: If True, bypass cache and check GitHub
        
    Returns:
        dict with keys:
            - current_version: str
            - latest_version: str or None
            - update_available: bool
            - release_url: str or None
            - release_notes: str or None
            - changelog: str or None
            - error: str or None
            - cached: bool
    """
    global _version_cache
    
    # Check cache first
    if not force_refresh and _version_cache['data'] and _version_cache['timestamp']:
        cache_age = time.time() - _version_cache['timestamp']
        if cache_age < _version_cache['cache_duration']:
            result = _version_cache['data'].copy()
            result['cached'] = True
            return result
    
    # Get GitHub config
    github_config = get_github_repo_config()
    repo = github_config['repo']
    branch = github_config['branch']
    
    result = {
        'current_version': current_version,
        'latest_version': None,
        'update_available': False,
        'release_url': None,
        'release_notes': None,
        'changelog': None,
        'error': None,
        'cached': False
    }
    
    try:
        # Try to get latest release first (more reliable)
        release_url = f"https://api.github.com/repos/{repo}/releases/latest"
        response = requests.get(release_url, timeout=5)
        
        if response.status_code == 200:
            release_data = response.json()
            latest_version = release_data.get('tag_name', '').lstrip('v')
            result['latest_version'] = latest_version
            result['release_url'] = release_data.get('html_url')
            result['release_notes'] = release_data.get('body', '')[:500]  # First 500 chars
            
            # Try to get changelog for this version
            try:
                changelog_url = f"https://raw.githubusercontent.com/{repo}/{branch}/CHANGELOG.md"
                changelog_response = requests.get(changelog_url, timeout=5)
                if changelog_response.status_code == 200:
                    changelog_content = changelog_response.text
                    # Extract changelog entry for this version
                    pattern = rf'## \[{re.escape(latest_version)}\].*?(?=## \[|\Z)'
                    match = re.search(pattern, changelog_content, re.DOTALL)
                    if match:
                        result['changelog'] = match.group(0).strip()
                    else:
                        # Try without brackets
                        pattern = rf'## {re.escape(latest_version)}.*?(?=## |\Z)'
                        match = re.search(pattern, changelog_content, re.DOTALL)
                        if match:
                            result['changelog'] = match.group(0).strip()
            except Exception as e:
                logger.debug(f"Could not fetch changelog: {e}")
            
            result['update_available'] = _compare_versions(current_version, latest_version) < 0
        elif response.status_code == 404:
            # No releases, try to get version from branch
            logger.info("No releases found, checking branch for version")
            branch_url = f"https://api.github.com/repos/{repo}/branches/{branch}"
            branch_response = requests.get(branch_url, timeout=5)
            
            if branch_response.status_code == 200:
                branch_data = branch_response.json()
                commit_sha = branch_data['commit']['sha']
                
                # Try to get version from version.py in the branch
                version_file_url = f"https://raw.githubusercontent.com/{repo}/{branch}/app/version.py"
                version_response = requests.get(version_file_url, timeout=5)
                
                if version_response.status_code == 200:
                    # Parse version from file content
                    content = version_response.text
                    for line in content.split('\n'):
                        if '__version__' in line:
                            # Extract version string
                            import re
                            match = re.search(r'["\']([^"\']+)["\']', line)
                            if match:
                                latest_version = match.group(1)
                                result['latest_version'] = latest_version
                                result['update_available'] = _compare_versions(current_version, latest_version) < 0
                                result['release_url'] = f"https://github.com/{repo}/tree/{branch}"
                                
                                # Try to get changelog for this version
                                try:
                                    changelog_url = f"https://raw.githubusercontent.com/{repo}/{branch}/CHANGELOG.md"
                                    changelog_response = requests.get(changelog_url, timeout=5)
                                    if changelog_response.status_code == 200:
                                        changelog_content = changelog_response.text
                                        # Extract changelog entry for this version
                                        pattern = rf'## \[{re.escape(latest_version)}\].*?(?=## \[|\Z)'
                                        match_changelog = re.search(pattern, changelog_content, re.DOTALL)
                                        if match_changelog:
                                            result['changelog'] = match_changelog.group(0).strip()
                                        else:
                                            # Try without brackets or get latest entry
                                            pattern = r'## \[([^\]]+)\].*?(?=## \[|\Z)'
                                            match_latest = re.search(pattern, changelog_content, re.DOTALL)
                                            if match_latest:
                                                result['changelog'] = match_latest.group(0).strip()
                                except Exception as e:
                                    logger.debug(f"Could not fetch changelog: {e}")
                                
                                break
            else:
                result['error'] = f"Could not access branch {branch}"
        else:
            result['error'] = f"GitHub API returned status {response.status_code}"
            
    except requests.exceptions.Timeout:
        result['error'] = "Connection timeout - GitHub may be unreachable"
        logger.warning("GitHub version check timed out")
    except requests.exceptions.RequestException as e:
        result['error'] = f"Network error: {str(e)}"
        logger.warning(f"GitHub version check failed: {e}")
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
        logger.error(f"GitHub version check error: {e}", exc_info=True)
    
    # Update cache
    _version_cache['data'] = result.copy()
    _version_cache['timestamp'] = time.time()
    
    return result

def _compare_versions(v1, v2):
    """
    Compare two version strings (e.g., "1.2.3" vs "1.2.4")
    
    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    if not v1 or not v2:
        return 0
    
    def version_tuple(v):
        # Split version string into tuple of integers
        parts = []
        for part in v.split('.'):
            try:
                parts.append(int(part))
            except ValueError:
                # Handle non-numeric parts (e.g., "1.2.3-beta")
                try:
                    parts.append(int(part.split('-')[0]))
                except:
                    parts.append(0)
        return tuple(parts)
    
    try:
        t1 = version_tuple(v1)
        t2 = version_tuple(v2)
        
        if t1 < t2:
            return -1
        elif t1 > t2:
            return 1
        else:
            return 0
    except Exception:
        # If comparison fails, do string comparison
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0

def get_version_info():
    """
    Get version information for display in templates
    
    Returns:
        dict with version information
    """
    version_data = check_github_version()
    
    return {
        'current_version': version_data['current_version'],
        'latest_version': version_data['latest_version'],
        'update_available': version_data['update_available'],
        'release_url': version_data['release_url'],
        'changelog': version_data.get('changelog'),
        'has_error': version_data['error'] is not None,
        'error_message': version_data['error'],
        'cached': version_data['cached']
    }

