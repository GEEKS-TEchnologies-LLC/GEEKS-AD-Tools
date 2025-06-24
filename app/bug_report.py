import os
import json
import platform
import subprocess
from datetime import datetime
from flask import request
from .models import AuditLog, db
from .ad import get_ad_config

def collect_system_info():
    """Collect system information for bug reports"""
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

def save_bug_report(report):
    """Save bug report to file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'bug_reports/bug_report_{timestamp}.json'
    
    # Create bug_reports directory if it doesn't exist
    os.makedirs('bug_reports', exist_ok=True)
    
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return filename
    except Exception as e:
        return None

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