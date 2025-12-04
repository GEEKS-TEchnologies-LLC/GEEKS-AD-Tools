import os
import json
import platform
import subprocess
import requests
from datetime import datetime
from flask import request, current_app
from .models import AuditLog, db
from .ad import get_ad_config

def collect_system_info():
    """Collect system information for bug reports"""
    import psutil
    import distro
    
    info = {
        'timestamp': datetime.utcnow().isoformat(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'system': platform.system(),
        'architecture': platform.architecture()[0],
        'hostname': platform.node(),
        'app_version': get_app_version(),
        'ad_configured': bool(get_ad_config()),
    }
    
    # Processor information
    try:
        info['processor'] = {
            'name': platform.processor(),
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'cpu_percent': psutil.cpu_percent(interval=1),
        }
    except Exception as e:
        info['processor'] = {'error': str(e)}
    
    # RAM information
    try:
        mem = psutil.virtual_memory()
        info['memory'] = {
            'total_gb': round(mem.total / (1024**3), 2),
            'available_gb': round(mem.available / (1024**3), 2),
            'used_gb': round(mem.used / (1024**3), 2),
            'percent': mem.percent,
        }
    except Exception as e:
        info['memory'] = {'error': str(e)}
    
    # Storage information
    try:
        disk = psutil.disk_usage('/')
        info['storage'] = {
            'total_gb': round(disk.total / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'percent': round((disk.used / disk.total) * 100, 2),
        }
    except Exception as e:
        info['storage'] = {'error': str(e)}
    
    # Kernel information
    try:
        import os
        uname = os.uname()
        info['kernel'] = {
            'system': uname.sysname,
            'release': uname.release,
            'version': uname.version,
            'machine': uname.machine,
        }
    except Exception as e:
        info['kernel'] = {'error': str(e)}
    
    # Distribution information (Linux)
    try:
        if platform.system() == 'Linux':
            dist_info = distro.linux_distribution(full_distribution_name=False)
            info['distribution'] = {
                'id': distro.id(),
                'name': distro.name(),
                'version': distro.version(),
                'codename': distro.codename(),
                'full_name': ' '.join(dist_info),
            }
        else:
            info['distribution'] = {'system': platform.system()}
    except Exception as e:
        info['distribution'] = {'error': str(e)}
    
    return info

def get_app_version():
    """Get the current app version"""
    try:
        with open('app/version.py', 'r') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().replace('"', '').replace("'", "")
    except:
        return 'Unknown'

def collect_recent_logs(lines=100):
    """Collect recent application logs"""
    logs = []
    
    # Collect Flask app logs
    log_path = 'app/logs/app.log'
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                logs.extend(f.readlines()[-lines:])
        except Exception as e:
            logs.append(f"Error reading app log: {e}")
    
    # Collect recent audit logs
    try:
        audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
        logs.append("\n=== Recent Audit Logs ===\n")
        for log in audit_logs:
            logs.append(f"{log.timestamp}: {log.user} - {log.action} - {log.result}\n")
    except Exception as e:
        logs.append(f"Error reading audit logs: {e}")
    
    return logs

def collect_error_logs():
    """Collect error-specific logs"""
    error_logs = []
    
    # Collect system errors
    try:
        result = subprocess.run(['systemctl', 'status', '--no-pager'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            error_logs.append("=== System Status ===\n")
            error_logs.append(result.stdout)
    except:
        pass
    
    # Collect any error files
    error_files = ['error.log', 'debug.log', 'trace.log']
    for error_file in error_files:
        if os.path.exists(error_file):
            try:
                with open(error_file, 'r') as f:
                    error_logs.append(f"\n=== {error_file} ===\n")
                    error_logs.extend(f.readlines()[-50:])
            except Exception as e:
                error_logs.append(f"Error reading {error_file}: {e}")
    
    return error_logs

def collect_config_info():
    """Collect configuration information (sanitized)"""
    config = {}
    
    # AD config (sanitized)
    ad_config = get_ad_config()
    if ad_config:
        config['ad'] = {
            'server': ad_config.get('ad_server', ''),
            'port': ad_config.get('ad_port', ''),
            'base_dn': ad_config.get('ad_base_dn', ''),
            'admin_groups': ad_config.get('admin_groups', []),
            'bind_dn': '***REDACTED***'  # Don't include credentials
        }
    
    # App config
    config['app'] = {
        'debug': os.environ.get('FLASK_DEBUG', 'False'),
        'secret_key_set': bool(os.environ.get('SECRET_KEY')),
        'database_path': 'app.db'
    }
    
    return config

def generate_bug_report(description, user_email=None, include_logs=True, include_config=True):
    """Generate a comprehensive bug report"""
    report = {
        'description': description,
        'user_email': user_email,
        'system_info': collect_system_info(),
        'request_info': {
            'user_agent': request.headers.get('User-Agent', ''),
            'ip_address': request.remote_addr,
            'url': request.url,
            'method': request.method
        }
    }
    
    if include_logs:
        report['logs'] = {
            'recent_logs': collect_recent_logs(),
            'error_logs': collect_error_logs()
        }
    
    if include_config:
        report['config'] = collect_config_info()
    
    return report

def get_github_config():
    """Get GitHub repository configuration"""
    try:
        from .credentials import get_credential
        
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Try to get token from secure storage first, then environment variable
                token = get_credential('github_token', '') or os.environ.get('GITHUB_TOKEN', '')
                return {
                    'repo': config.get('github_repo', ''),
                    'token': token
                }
    except Exception as e:
        try:
            if current_app:
                current_app.logger.warning(f"Error reading GitHub config: {e}")
        except:
            pass  # current_app not available
    return {'repo': '', 'token': ''}

def create_github_issue(report):
    """Create a GitHub issue from bug report"""
    github_config = get_github_config()
    repo = github_config.get('repo', '')
    token = github_config.get('token', '')
    
    if not repo:
        return None, "GitHub repository not configured"
    
    if not token:
        return None, "GitHub token not configured. Please configure it in Admin Settings > Bug Reporting."
    
    # Format issue title
    title = f"Bug Report: {report.get('description', 'No description')[:100]}"
    if len(report.get('description', '')) > 100:
        title += "..."
    
    # Format issue body
    body_parts = []
    body_parts.append("## Bug Description\n")
    body_parts.append(report.get('description', 'No description provided'))
    body_parts.append("\n\n")
    
    # System information
    if report.get('system_info'):
        sys_info = report['system_info']
        body_parts.append("## System Information\n")
        body_parts.append(f"- **Version**: {sys_info.get('app_version', 'Unknown')}\n")
        body_parts.append(f"- **Platform**: {sys_info.get('platform', 'Unknown')}\n")
        body_parts.append(f"- **Python**: {sys_info.get('python_version', 'Unknown')}\n")
        body_parts.append(f"- **Hostname**: {sys_info.get('hostname', 'Unknown')}\n")
        body_parts.append(f"- **Timestamp**: {sys_info.get('timestamp', 'Unknown')}\n")
        body_parts.append("\n")
    
    # Request information
    if report.get('request_info'):
        req_info = report['request_info']
        body_parts.append("## Request Information\n")
        body_parts.append(f"- **URL**: {req_info.get('url', 'Unknown')}\n")
        body_parts.append(f"- **Method**: {req_info.get('method', 'Unknown')}\n")
        body_parts.append(f"- **IP Address**: {req_info.get('ip_address', 'Unknown')}\n")
        body_parts.append(f"- **User Agent**: {req_info.get('user_agent', 'Unknown')}\n")
        body_parts.append("\n")
    
    # Configuration (sanitized)
    if report.get('config'):
        config = report['config']
        body_parts.append("## Configuration\n")
        body_parts.append("```json\n")
        body_parts.append(json.dumps(config, indent=2))
        body_parts.append("\n```\n\n")
    
    # Logs (if included)
    if report.get('logs'):
        logs = report['logs']
        if logs.get('recent_logs'):
            body_parts.append("## Recent Logs\n")
            body_parts.append("<details><summary>Click to expand logs</summary>\n\n")
            body_parts.append("```\n")
            body_parts.append(''.join(logs['recent_logs'][-50:]))  # Last 50 lines
            body_parts.append("\n```\n")
            body_parts.append("</details>\n\n")
        
        if logs.get('error_logs'):
            body_parts.append("## Error Logs\n")
            body_parts.append("<details><summary>Click to expand error logs</summary>\n\n")
            body_parts.append("```\n")
            body_parts.append(''.join(logs['error_logs'][-50:]))  # Last 50 lines
            body_parts.append("\n```\n")
            body_parts.append("</details>\n\n")
    
    # Reporter information
    if report.get('user_email'):
        body_parts.append(f"**Reported by**: {report['user_email']}\n")
    
    body = ''.join(body_parts)
    
    # Create issue via GitHub API
    try:
        # Parse repo owner and name
        if '/' in repo:
            owner, repo_name = repo.split('/', 1)
        else:
            return None, "Invalid repository format (expected: owner/repo)"
        
        url = f"https://api.github.com/repos/{owner}/{repo_name}/issues"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        data = {
            'title': title,
            'body': body,
            'labels': ['bug', 'user-reported']
        }
        
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 201:
            issue_data = response.json()
            issue_url = issue_data.get('html_url', '')
            issue_number = issue_data.get('number', '')
            return issue_url, f"Issue #{issue_number} created successfully"
        else:
            error_msg = f"GitHub API error: {response.status_code} - {response.text[:500]}"
            try:
                if current_app:
                    current_app.logger.error(error_msg)
            except:
                pass  # current_app not available
            return None, error_msg
            
    except requests.exceptions.RequestException as e:
        error_msg = f"Error creating GitHub issue: {str(e)}"
        try:
            if current_app:
                current_app.logger.error(error_msg)
        except:
            pass  # current_app not available
        return None, error_msg
    except Exception as e:
        error_msg = f"Unexpected error creating GitHub issue: {str(e)}"
        try:
            if current_app:
                current_app.logger.error(error_msg)
        except:
            pass  # current_app not available
        return None, error_msg

def save_bug_report(report):
    """Save bug report to file and create GitHub issue"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'bug_reports/bug_report_{timestamp}.json'
    
    # Create bug_reports directory if it doesn't exist
    os.makedirs('bug_reports', exist_ok=True)
    
    # Try to create GitHub issue first
    issue_url = None
    issue_message = None
    try:
        issue_url, issue_message = create_github_issue(report)
        if issue_url:
            report['github_issue_url'] = issue_url
            report['github_issue_message'] = issue_message
    except Exception as e:
        try:
            if current_app:
                current_app.logger.error(f"Error creating GitHub issue: {e}")
        except:
            pass  # current_app not available
        issue_message = f"Failed to create GitHub issue: {str(e)}"
    
    # Save to file as backup
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Return filename and issue info
        return {
            'filename': filename,
            'github_issue_url': issue_url,
            'github_issue_message': issue_message
        }
    except Exception as e:
        try:
            if current_app:
                current_app.logger.error(f"Error saving bug report: {e}")
        except:
            pass  # current_app not available
        return {
            'filename': None,
            'github_issue_url': issue_url,
            'github_issue_message': issue_message or f"Failed to save: {str(e)}"
        }

def get_bug_report_summary():
    """Get summary of existing bug reports"""
    if not os.path.exists('bug_reports'):
        return []
    
    reports = []
    for filename in os.listdir('bug_reports'):
        if filename.endswith('.json'):
            try:
                with open(f'bug_reports/{filename}', 'r') as f:
                    report = json.load(f)
                    reports.append({
                        'filename': filename,
                        'timestamp': report.get('system_info', {}).get('timestamp', ''),
                        'description': report.get('description', '')[:100] + '...' if len(report.get('description', '')) > 100 else report.get('description', ''),
                        'user_email': report.get('user_email', '')
                    })
            except:
                continue
    
    return sorted(reports, key=lambda x: x['timestamp'], reverse=True) 