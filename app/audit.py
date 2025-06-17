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

def log_login(username, result='success', details=None):
    """Log login attempts"""
    log_event('login', result, details, username)

def log_password_reset(username, result='success', details=None):
    """Log password reset attempts"""
    log_event('password_reset', result, details, username)

def log_user_action(action, username, result='success', details=None):
    """Log user management actions"""
    log_event(f'user_{action}', result, details, username)

def log_admin_action(action, result='success', details=None):
    """Log admin actions"""
    log_event(f'admin_{action}', result, details)

def log_system_event(action, result='success', details=None):
    """Log system events"""
    log_event(f'system_{action}', result, details, 'System')

def get_audit_logs(start_date=None, end_date=None, user=None, action=None, result=None, limit=100):
    """Retrieve audit logs with filtering"""
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

def export_audit_logs_csv(start_date=None, end_date=None, user=None, action=None, result=None):
    """Export audit logs to CSV format"""
    import csv
    import io
    
    logs = get_audit_logs(start_date, end_date, user, action, result, limit=10000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp', 'User', 'Action', 'Details', 'Result', 'IP Address', 'User Agent'])
    
    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user,
            log.action,
            log.details,
            log.result,
            log.ip_address,
            log.user_agent
        ])
    
    return output.getvalue()

def get_audit_stats(days=30):
    """Get audit statistics for the dashboard"""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Total events
    total_events = AuditLog.query.filter(AuditLog.timestamp >= start_date).count()
    
    # Events by result
    success_events = AuditLog.query.filter(
        AuditLog.timestamp >= start_date,
        AuditLog.result == 'success'
    ).count()
    
    failure_events = AuditLog.query.filter(
        AuditLog.timestamp >= start_date,
        AuditLog.result == 'failure'
    ).count()
    
    # Top actions
    from sqlalchemy import func
    top_actions = db.session.query(
        AuditLog.action,
        func.count(AuditLog.id).label('count')
    ).filter(
        AuditLog.timestamp >= start_date
    ).group_by(AuditLog.action).order_by(func.count(AuditLog.id).desc()).limit(5).all()
    
    return {
        'total_events': total_events,
        'success_events': success_events,
        'failure_events': failure_events,
        'top_actions': top_actions
    } 