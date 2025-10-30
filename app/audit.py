import json
from flask import request, session
from flask_login import current_user
from .models import AuditLog, db
from datetime import datetime, timedelta

def log_event(action, result='success', details=None, user=None, ip_address=None, user_agent=None):
    """Centralized function to log audit events"""
    try:
        # Get user info
        if user is None:
            user = current_user.username if current_user.is_authenticated else 'Anonymous'
        
        # Get request info if available
        if ip_address is None and request:
            ip_address = request.remote_addr
        if user_agent is None and request:
            user_agent = request.headers.get('User-Agent', '')
        
        # Get session ID
        session_id = session.get('session_id', '') if session else ''
        
        # Convert details to JSON if it's a dict
        if isinstance(details, dict):
            details = json.dumps(details)
        
        # Create audit log entry
        audit_log = AuditLog(
            user=user,
            action=action,
            details=details,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        # Fallback to file logging if database fails
        import logging
        logging.error(f"Failed to log audit event: {e}")
        # Don't re-raise the exception to prevent application crashes
        # Just log the error and continue

def log_login(username, result, details=None):
    """Log login attempts"""
    log_event('login', result, details, username)

def log_password_reset(username, result, details=None):
    """Log password reset attempts"""
    log_event('password_reset', result, details, username)

def log_user_action(action, username, result, details=None):
    """Log user management actions
    Args:
        action: The action being performed (e.g., 'create', 'delete', 'search')
        username: The target username being acted upon
        result: 'success', 'failure', or 'error'
        details: Additional details (dict or string). Will include target_username if not already present.
    """
    # Get the logged-in user performing the action
    performed_by = current_user.username if current_user.is_authenticated else 'Anonymous'
    
    # Include target username in details if it's a dict and not already present
    if details is None:
        details = {}
    if isinstance(details, dict):
        if 'target_username' not in details and username:
            details['target_username'] = username
    elif isinstance(details, str) and username:
        # If details is a string, try to parse it as JSON and add target_username
        try:
            details_dict = json.loads(details)
            details_dict['target_username'] = username
            details = details_dict
        except (json.JSONDecodeError, TypeError):
            # If parsing fails, create a new dict
            details = {'details': details, 'target_username': username}
    
    # Use the logged-in user as the user field
    log_event(f'user_{action}', result, details, performed_by)

def log_admin_action(action, result, details=None):
    """Log admin actions"""
    # Explicitly get the logged-in user performing the action
    performed_by = current_user.username if current_user.is_authenticated else 'Anonymous'
    log_event(f'admin_{action}', result, details, performed_by)

def log_system_event(event, result, details=None):
    """Log system events"""
    log_event(f'system_{event}', result, details, user='System')

def get_audit_logs(start_date=None, end_date=None, user=None, action=None, result=None, limit=100):
    """Get audit logs with optional filtering"""
    try:
        query = AuditLog.query
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        if user:
            query = query.filter(AuditLog.user.like(f'%{user}%'))
        if action:
            query = query.filter(AuditLog.action.like(f'%{action}%'))
        if result:
            query = query.filter(AuditLog.result == result)
        
        return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    except Exception as e:
        import logging
        logging.error(f"Failed to get audit logs: {e}")
        return []

def export_audit_logs_csv(start_date=None, end_date=None, user=None, action=None, result=None):
    """Export audit logs to CSV format"""
    try:
        logs = get_audit_logs(start_date, end_date, user, action, result, limit=10000)
        
        csv_data = "Timestamp,User,Action,Details,Result,IP Address,User Agent\n"
        for log in logs:
            details = log.details.replace('"', '""') if log.details else ''
            csv_data += f'"{log.timestamp}","{log.user}","{log.action}","{details}","{log.result}","{log.ip_address}","{log.user_agent}"\n'
        
        return csv_data
    except Exception as e:
        import logging
        logging.error(f"Failed to export audit logs: {e}")
        return ""

def get_audit_stats(days=30):
    """Get audit statistics for the last N days"""
    try:
        from datetime import datetime, timedelta
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get total events
        total_events = AuditLog.query.filter(AuditLog.timestamp >= start_date).count()
        
        # Get events by result
        success_events = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.result == 'success'
        ).count()
        
        failure_events = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.result == 'failure'
        ).count()
        
        error_events = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.result == 'error'
        ).count()
        
        # Get top actions
        from sqlalchemy import func
        top_actions = db.session.query(
            AuditLog.action,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.timestamp >= start_date
        ).group_by(AuditLog.action).order_by(
            func.count(AuditLog.id).desc()
        ).limit(5).all()
        
        return {
            'total_events': total_events,
            'success_events': success_events,
            'failure_events': failure_events,
            'error_events': error_events,
            'top_actions': [(action, count) for action, count in top_actions]
        }
    except Exception as e:
        import logging
        logging.error(f"Failed to get audit stats: {e}")
        return {
            'total_events': 0,
            'success_events': 0,
            'failure_events': 0,
            'error_events': 0,
            'top_actions': []
        } 