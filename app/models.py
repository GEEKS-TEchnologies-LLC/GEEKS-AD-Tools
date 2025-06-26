from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from datetime import datetime, timedelta, timezone

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    user = db.Column(db.String(64), nullable=True)  # Username or 'System'
    action = db.Column(db.String(128), nullable=False)  # e.g., 'login', 'password_reset', 'user_create'
    details = db.Column(db.Text, nullable=True)  # Additional details in JSON format
    result = db.Column(db.String(32), nullable=False)  # 'success', 'failure', 'error'
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    session_id = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f'<AuditLog {self.timestamp}: {self.user} - {self.action} - {self.result}>'

class SecurityQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    question_number = db.Column(db.Integer, nullable=False, default=1)  # 1, 2, or 3
    question = db.Column(db.String(256), nullable=False)
    answer_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    
    # Composite unique constraint to ensure one question per number per user
    __table_args__ = (db.UniqueConstraint('username', 'question_number', name='_user_question_number_uc'),)

    def set_answer(self, answer):
        self.answer_hash = generate_password_hash(answer)

    def check_answer(self, answer):
        return check_password_hash(self.answer_hash, answer)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    reset_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    reset_by = db.Column(db.String(64), nullable=True)  # admin username if reset by admin
    method = db.Column(db.String(32), nullable=False)  # 'self', 'admin', 'security_question'
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    success = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    
    def days_since_reset(self):
        """Calculate days since this password reset"""
        return (datetime.now(timezone.utc) - self.reset_at).days
    
    def is_recent(self, days=7):
        """Check if reset was within specified days"""
        return self.days_since_reset() <= days

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    task_type = db.Column(db.String(64), nullable=False)  # 'security_question', 'verify_info', etc.
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), default='pending', nullable=False)  # pending, completed, expired
    assigned_by = db.Column(db.String(64), nullable=False)  # admin username
    assigned_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.String(32), default='medium', nullable=False)  # low, medium, high, urgent
    
    # Task-specific data (JSON)
    task_data = db.Column(db.Text, nullable=True)  # JSON string for additional data
    
    def is_overdue(self):
        if self.due_date and self.status == 'pending':
            return datetime.now(timezone.utc) > self.due_date
        return False
    
    def days_until_due(self):
        if self.due_date and self.status == 'pending':
            delta = self.due_date - datetime.now(timezone.utc)
            return delta.days
        return None
    
    def get_task_data(self):
        """Parse task_data JSON and return as dict"""
        if self.task_data:
            try:
                import json
                return json.loads(self.task_data)
            except:
                return {}
        return {}
    
    def set_task_data(self, data):
        """Store task data as JSON string"""
        import json
        self.task_data = json.dumps(data)

# Helper functions for password reset tracking
def get_password_policy():
    """Get password policy settings from branding config"""
    from app.views import get_branding_config
    branding = get_branding_config() or {}
    return {
        'max_age_days': branding.get('password_max_age_days', 90),
        'warning_days': branding.get('password_warning_days', 14),
        'min_length': branding.get('password_min_length', 8),
        'require_complexity': branding.get('password_require_complexity', True)
    }

def get_last_password_reset(username):
    """Get the most recent successful password reset for a user"""
    return PasswordReset.query.filter_by(
        username=username, 
        success=True
    ).order_by(PasswordReset.reset_at.desc()).first()

def get_password_reset_history(username, limit=10):
    """Get recent password reset history for a user"""
    return PasswordReset.query.filter_by(username=username).order_by(
        PasswordReset.reset_at.desc()
    ).limit(limit).all()

def calculate_days_until_reset(username):
    """Calculate days until password reset is required"""
    policy = get_password_policy()
    last_reset = get_last_password_reset(username)
    
    if not last_reset:
        return 0  # No previous reset, should reset now
    
    days_since = last_reset.days_since_reset()
    days_until = policy['max_age_days'] - days_since
    
    return max(0, days_until)

def is_password_expired(username):
    """Check if user's password is expired"""
    return calculate_days_until_reset(username) <= 0

def is_password_expiring_soon(username):
    """Check if user's password is expiring soon"""
    policy = get_password_policy()
    days_until = calculate_days_until_reset(username)
    return 0 < days_until <= policy['warning_days']

def get_ad_password_policy(username=None):
    """Get password policy from Active Directory"""
    from app.views import get_ad_config, search_users
    
    config = get_ad_config()
    if not config:
        return None
    
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE
        
        # Connect to AD
        server = Server(config['ad_server'], port=int(config['ad_port']), get_info=ALL)
        conn = Connection(server, 
                         user=config['ad_bind_dn'], 
                         password=config['ad_password'], 
                         auto_bind=True)
        
        # Search for domain policy
        domain_dn = config['ad_base_dn']
        conn.search(domain_dn, 
                   '(objectClass=domain)', 
                   attributes=['maxPwdAge', 'minPwdLength', 'pwdHistoryLength'])
        
        if conn.entries:
            domain = conn.entries[0]
            
            # Convert AD time format to days (AD stores as negative 100-nanosecond intervals)
            max_pwd_age = None
            if domain.maxPwdAge and domain.maxPwdAge.value != 0:
                max_age = domain.maxPwdAge.value
                if isinstance(max_age, timedelta):
                    max_pwd_age = int(max_age.total_seconds() // 86400)
                elif isinstance(max_age, (int, float)):
                    # Convert from AD time format to days (AD stores as negative 100-nanosecond intervals)
                    max_pwd_age = abs(max_age) // (10**7 * 60 * 60 * 24)
                else:
                    max_pwd_age = 0
            
            domain_policy = {
                'max_age_days': max_pwd_age if max_pwd_age else 0,
                'min_length': domain.minPwdLength.value if domain.minPwdLength else 0,
                'history_count': domain.pwdHistoryLength.value if domain.pwdHistoryLength else 0
            }
            
            # If we have a specific user, also check their account settings
            if username:
                users = search_users(username, **{
                    'server': config['ad_server'],
                    'port': int(config['ad_port']),
                    'bind_user': config['ad_bind_dn'],
                    'bind_password': config['ad_password'],
                    'base_dn': config['ad_base_dn']
                })
                
                if users:
                    user_dn = users[0]['dn']
                    conn.search(user_dn, '(objectClass=user)', 
                              attributes=['pwdLastSet', 'userAccountControl', 
                                        'lockoutTime', 'accountExpires', 'lastLogon', 'lastLogonTimestamp'])
                    
                    if conn.entries:
                        user = conn.entries[0]
                        
                        # Check if password never expires
                        uac = user.userAccountControl.value if user.userAccountControl else 0
                        password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD flag
                        
                        if password_never_expires:
                            domain_policy['max_age_days'] = 0
                        
                        # Check if password is set to change at next logon
                        pwd_last_set = user.pwdLastSet.value if user.pwdLastSet else 0
                        if pwd_last_set == 0:
                            domain_policy['force_change'] = True
                        else:
                            domain_policy['force_change'] = False
            
            conn.unbind()
            return domain_policy
            
    except Exception as e:
        print(f"Error retrieving AD password policy: {e}")
        return None
    
    return None

def validate_password_against_ad_policy(password, username=None):
    """Validate password against AD policy requirements"""
    ad_policy = get_ad_password_policy(username)
    if not ad_policy:
        # Fall back to local policy if AD policy can't be retrieved
        return validate_password_against_local_policy(password)
    
    errors = []
    
    # Check minimum length
    if len(password) < ad_policy['min_length']:
        errors.append(f"Password must be at least {ad_policy['min_length']} characters long")
    
    # Check complexity requirements
    if ad_policy['require_complexity'] or ad_policy['complexity_enabled']:
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if not has_upper:
            errors.append("Password must contain at least one uppercase letter")
        if not has_lower:
            errors.append("Password must contain at least one lowercase letter")
        if not has_digit:
            errors.append("Password must contain at least one number")
        if not has_special:
            errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors

def validate_password_against_local_policy(password):
    """Validate password against local policy (fallback)"""
    policy = get_password_policy()
    errors = []
    
    if len(password) < policy['min_length']:
        errors.append(f"Password must be at least {policy['min_length']} characters long")
    
    if policy['require_complexity']:
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            errors.append("Password must contain uppercase, lowercase, digit, and special character")
    
    return len(errors) == 0, errors

def get_dynamic_password_requirements(username=None):
    """Get password requirements based on AD policy and user context"""
    ad_policy = get_ad_password_policy(username)
    if not ad_policy:
        # Fall back to local policy
        policy = get_password_policy()
        return {
            'min_length': policy['min_length'],
            'require_uppercase': policy['require_complexity'],
            'require_lowercase': policy['require_complexity'],
            'require_digit': policy['require_complexity'],
            'require_special': policy['require_complexity'],
            'max_age_days': policy['max_age_days'],
            'warning_days': policy['warning_days'],
            'source': 'local'
        }
    
    return {
        'min_length': ad_policy['min_length'],
        'require_uppercase': ad_policy['require_complexity'] or ad_policy['complexity_enabled'],
        'require_lowercase': ad_policy['require_complexity'] or ad_policy['complexity_enabled'],
        'require_digit': ad_policy['require_complexity'] or ad_policy['complexity_enabled'],
        'require_special': ad_policy['require_complexity'] or ad_policy['complexity_enabled'],
        'max_age_days': ad_policy['max_age_days'],
        'history_count': ad_policy['history_count'],
        'force_change': ad_policy.get('force_change', False),
        'source': 'active_directory'
    }

def get_ad_password_info(username):
    """Get detailed password information from Active Directory"""
    from app.views import get_ad_config, search_users
    
    config = get_ad_config()
    if not config:
        return None
    
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE
        from datetime import datetime, timezone
        
        # Connect to AD
        server = Server(config['ad_server'], port=int(config['ad_port']), get_info=ALL)
        conn = Connection(server, 
                         user=config['ad_bind_dn'], 
                         password=config['ad_password'], 
                         auto_bind=True)
        
        # Search for user
        users = search_users(username, **{
            'server': config['ad_server'],
            'port': int(config['ad_port']),
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        })
        
        if not users:
            conn.unbind()
            return None
        
        user_dn = users[0]['dn']
        
        # Get user's password-related attributes
        conn.search(user_dn, '(objectClass=user)', 
                   attributes=['pwdLastSet', 'userAccountControl', 
                             'lockoutTime', 'accountExpires', 'lastLogon', 'lastLogonTimestamp'])
        
        if not conn.entries:
            conn.unbind()
            return None
        
        user = conn.entries[0]
        
        # Get domain password policy for context
        domain_dn = config['ad_base_dn']
        conn.search(domain_dn, '(objectClass=domain)', 
                   attributes=['maxPwdAge', 'minPwdLength', 'pwdHistoryLength'])
        
        domain_policy = None
        if conn.entries:
            domain = conn.entries[0]
            max_pwd_age = None
            if domain.maxPwdAge and domain.maxPwdAge.value != 0:
                max_age = domain.maxPwdAge.value
                if isinstance(max_age, timedelta):
                    max_pwd_age = int(max_age.total_seconds() // 86400)
                elif isinstance(max_age, (int, float)):
                    # Convert from AD time format to days (AD stores as negative 100-nanosecond intervals)
                    max_pwd_age = abs(max_age) // (10**7 * 60 * 60 * 24)
                else:
                    max_pwd_age = 0
            
            domain_policy = {
                'max_age_days': max_pwd_age if max_pwd_age else 0,
                'min_length': domain.minPwdLength.value if domain.minPwdLength else 0,
                'history_count': domain.pwdHistoryLength.value if domain.pwdHistoryLength else 0
            }
        
        # Parse user account control flags
        uac = user.userAccountControl.value if user.userAccountControl else 0
        password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
        account_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE
        password_not_required = bool(uac & 0x20)  # PASSWD_NOTREQD
        smart_card_required = bool(uac & 0x40000)  # SMARTCARD_REQUIRED
        
        # Parse password last set
        pwd_last_set = None
        if user.pwdLastSet and hasattr(user.pwdLastSet, 'value') and user.pwdLastSet.value and user.pwdLastSet.value != 0:
            ad_time = user.pwdLastSet.value
            if isinstance(ad_time, datetime):
                pwd_last_set = ad_time
            elif isinstance(ad_time, int) and ad_time > 0:
                seconds_since_1601 = ad_time // (10**7)
                seconds_since_1970 = seconds_since_1601 - 11644473600
                pwd_last_set = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        print(f"DEBUG: pwdLastSet raw: {getattr(user.pwdLastSet, 'value', None)} parsed: {pwd_last_set}")

        # Parse lockout time
        lockout_time = None
        if user.lockoutTime and hasattr(user.lockoutTime, 'value') and user.lockoutTime.value and user.lockoutTime.value != 0:
            ad_time = user.lockoutTime.value
            if isinstance(ad_time, datetime):
                lockout_time = ad_time
            elif isinstance(ad_time, int) and ad_time > 0:
                seconds_since_1601 = ad_time // (10**7)
                seconds_since_1970 = seconds_since_1601 - 11644473600
                lockout_time = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        print(f"DEBUG: lockoutTime raw: {getattr(user.lockoutTime, 'value', None)} parsed: {lockout_time}")

        # Parse account expiration
        account_expires = None
        if user.accountExpires and hasattr(user.accountExpires, 'value') and user.accountExpires.value and user.accountExpires.value != 0 and user.accountExpires.value != 9223372036854775807:
            ad_time = user.accountExpires.value
            if isinstance(ad_time, datetime):
                account_expires = ad_time
            elif isinstance(ad_time, int) and ad_time > 0:
                seconds_since_1601 = ad_time // (10**7)
                seconds_since_1970 = seconds_since_1601 - 11644473600
                account_expires = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        print(f"DEBUG: accountExpires raw: {getattr(user.accountExpires, 'value', None)} parsed: {account_expires}")

        # Parse last logon times
        last_logon = None
        if user.lastLogon and hasattr(user.lastLogon, 'value') and user.lastLogon.value and user.lastLogon.value != 0:
            ad_time = user.lastLogon.value
            if isinstance(ad_time, datetime):
                last_logon = ad_time
            elif isinstance(ad_time, int) and ad_time > 0:
                seconds_since_1601 = ad_time // (10**7)
                seconds_since_1970 = seconds_since_1601 - 11644473600
                last_logon = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        print(f"DEBUG: lastLogon raw: {getattr(user.lastLogon, 'value', None)} parsed: {last_logon}")

        last_logon_timestamp = None
        if user.lastLogonTimestamp and hasattr(user.lastLogonTimestamp, 'value') and user.lastLogonTimestamp.value and user.lastLogonTimestamp.value != 0:
            ad_time = user.lastLogonTimestamp.value
            if isinstance(ad_time, datetime):
                last_logon_timestamp = ad_time
            elif isinstance(ad_time, int) and ad_time > 0:
                seconds_since_1601 = ad_time // (10**7)
                seconds_since_1970 = seconds_since_1601 - 11644473600
                last_logon_timestamp = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        print(f"DEBUG: lastLogonTimestamp raw: {getattr(user.lastLogonTimestamp, 'value', None)} parsed: {last_logon_timestamp}")
        
        # Fix maxPwdAge to integer days
        max_pwd_age_days = None
        if domain_policy and 'max_age_days' in domain_policy:
            max_age = domain_policy['max_age_days']
            if isinstance(max_age, timedelta):
                max_pwd_age_days = int(max_age.total_seconds() // 86400)
            elif isinstance(max_age, (int, float)):
                max_pwd_age_days = int(max_age)
            else:
                max_pwd_age_days = 0
            domain_policy['max_age_days'] = max_pwd_age_days
        elif domain and domain.maxPwdAge and domain.maxPwdAge.value:
            # Handle case where maxPwdAge comes as timedelta directly from AD
            max_age = domain.maxPwdAge.value
            if isinstance(max_age, timedelta):
                max_pwd_age_days = int(max_age.total_seconds() // 86400)
            elif isinstance(max_age, (int, float)):
                # Convert from AD time format to days (AD stores as negative 100-nanosecond intervals)
                max_pwd_age_days = abs(max_age) // (10**7 * 60 * 60 * 24)
            else:
                max_pwd_age_days = 0
            
            if not domain_policy:
                domain_policy = {}
            domain_policy['max_age_days'] = max_pwd_age_days

        # Calculate password status
        password_status = "unknown"
        days_until_expiry = None
        days_since_last_set = None
        
        if pwd_last_set:
            days_since_last_set = (datetime.now(timezone.utc) - pwd_last_set).days
            
            if password_never_expires:
                password_status = "never_expires"
            elif domain_policy and max_pwd_age_days and max_pwd_age_days > 0:
                days_until_expiry = max_pwd_age_days - days_since_last_set
                if days_until_expiry <= 0:
                    password_status = "expired"
                elif days_until_expiry <= 14:  # Warning threshold
                    password_status = "expiring_soon"
                else:
                    password_status = "valid"
            else:
                password_status = "valid"
        
        # Check if password must be changed
        pwd_must_change = False  # Default value since attribute doesn't exist
        pwd_can_change = True    # Default value since attribute doesn't exist
        
        conn.unbind()
        
        # Debug logging for troubleshooting expiry logic
        print(f"DEBUG: pwdLastSet: {pwd_last_set}")
        if domain_policy:
            print(f"DEBUG: maxPwdAge (raw): {domain.maxPwdAge.value if 'domain' in locals() and hasattr(domain, 'maxPwdAge') and domain.maxPwdAge else 'N/A'}")
            print(f"DEBUG: maxPwdAge (days): {domain_policy['max_age_days']}")
        print(f"DEBUG: days_since_last_set: {days_since_last_set}")
        print(f"DEBUG: days_until_expiry: {days_until_expiry}")
        
        # Calculate is_locked_out safely
        is_locked_out = False
        if isinstance(lockout_time, datetime):
            is_locked_out = lockout_time > datetime.now(timezone.utc) - timedelta(minutes=30)
        # If lockout_time is not a datetime, treat as not locked out
        
        return {
            'username': username,
            'password_status': password_status,
            'password_never_expires': password_never_expires,
            'account_disabled': account_disabled,
            'password_not_required': password_not_required,
            'smart_card_required': smart_card_required,
            'pwd_last_set': pwd_last_set,
            'pwd_must_change': pwd_must_change,
            'pwd_can_change': pwd_can_change,
            'lockout_time': lockout_time,
            'account_expires': account_expires,
            'last_logon': last_logon,
            'last_logon_timestamp': last_logon_timestamp,
            'days_since_last_set': days_since_last_set,
            'days_until_expiry': days_until_expiry,
            'domain_policy': domain_policy,
            'is_locked_out': is_locked_out
        }
        
    except Exception as e:
        print(f"Error retrieving AD password info: {e}")
        return None

def get_ad_password_history(username):
    """Get password history from AD (if available)"""
    # Note: AD doesn't store actual password history, only the count
    # This function could be enhanced to check against our local PasswordReset table
    from app.models import get_password_reset_history
    
    # Get local password reset history
    local_history = get_password_reset_history(username, limit=20)
    
    # Get AD password info for context
    ad_info = get_ad_password_info(username)
    
    return {
        'local_history': local_history,
        'ad_info': ad_info,
        'history_count': ad_info['domain_policy']['history_count'] if ad_info and ad_info['domain_policy'] else 0
    }

def calculate_ad_password_age(username):
    """Calculate password age based on AD pwdLastSet attribute"""
    ad_info = get_ad_password_info(username)
    if not ad_info or not ad_info['pwd_last_set']:
        return None
    
    return {
        'last_set': ad_info['pwd_last_set'],
        'days_since_set': ad_info['days_since_last_set'],
        'days_until_expiry': ad_info['days_until_expiry'],
        'status': ad_info['password_status'],
        'never_expires': ad_info['password_never_expires']
    }

def get_ad_password_change_history(username, limit=10):
    """Get password change history from AD pwdLastSet attribute"""
    ad_info = get_ad_password_info(username)
    if not ad_info or not ad_info['pwd_last_set']:
        return []
    
    # Create a password reset record from AD data
    from app.models import PasswordReset
    
    # Check if we already have a local record for this
    existing_reset = PasswordReset.query.filter_by(
        username=username,
        reset_at=ad_info['pwd_last_set']
    ).first()
    
    if not existing_reset:
        # Create a record based on AD data
        reset_record = PasswordReset(
            username=username,
            reset_by='active_directory',
            ip_address='N/A',
            user_agent='Active Directory',
            success=True,
            notes=f'Password last set in AD: {ad_info["pwd_last_set"].strftime("%Y-%m-%d %H:%M UTC")}'
        )
        reset_record.reset_at = ad_info['pwd_last_set']
        # Don't actually save this to avoid duplicates, just return the info
        return [{
            'username': username,
            'reset_by': 'Active Directory',
            'ip_address': 'N/A',
            'user_agent': 'Active Directory',
            'success': True,
            'notes': f'Password last set in AD: {ad_info["pwd_last_set"].strftime("%Y-%m-%d %H:%M UTC")}',
            'reset_at': ad_info['pwd_last_set'],
            'days_since_reset': lambda: (datetime.now(timezone.utc) - ad_info['pwd_last_set']).days
        }]
    
    return []

def get_comprehensive_password_history(username, limit=20):
    """Get comprehensive password history combining local and AD data"""
    from app.models import get_password_reset_history
    
    # Get local password reset history
    local_history = get_password_reset_history(username, limit=limit)
    
    # Get AD password change info
    ad_info = get_ad_password_info(username)
    ad_history = get_ad_password_change_history(username, limit=limit)
    
    # Combine and sort by date
    all_history = []
    
    # Add local history
    for reset in local_history:
        all_history.append({
            'source': 'local',
            'data': reset
        })
    
    # Add AD history (if not already in local)
    for reset in ad_history:
        # Check if we already have this in local history
        exists = any(
            local_reset.reset_at == reset['reset_at'] 
            for local_reset in local_history
        )
        if not exists:
            all_history.append({
                'source': 'ad',
                'data': reset
            })
    
    # Sort by reset date (newest first)
    all_history.sort(key=lambda x: x['data'].reset_at if hasattr(x['data'], 'reset_at') else x['data']['reset_at'], reverse=True)
    
    return {
        'combined_history': all_history[:limit],
        'local_count': len(local_history),
        'ad_info': ad_info,
        'total_entries': len(all_history)
    }

def get_user_security_questions(username):
    """Get all security questions for a user"""
    return SecurityQuestion.query.filter_by(username=username).order_by(SecurityQuestion.question_number).all()

def get_user_security_question(username, question_number):
    """Get a specific security question for a user"""
    return SecurityQuestion.query.filter_by(username=username, question_number=question_number).first()

def get_next_security_question(username, last_used_question=None):
    """Get the next security question to ask, cycling through the available questions"""
    questions = get_user_security_questions(username)
    if not questions:
        return None
    
    if last_used_question is None:
        # First time, return the first question
        return questions[0]
    
    # Find the current question and return the next one
    current_index = None
    for i, q in enumerate(questions):
        if q.question_number == last_used_question:
            current_index = i
            break
    
    if current_index is None:
        return questions[0]
    
    # Return the next question, cycling back to the first
    next_index = (current_index + 1) % len(questions)
    return questions[next_index]

def has_complete_security_questions(username):
    """Check if user has all 3 security questions set up"""
    questions = get_user_security_questions(username)
    return len(questions) >= 3

def get_security_question_count(username):
    """Get the number of security questions set up for a user"""
    return SecurityQuestion.query.filter_by(username=username).count()

def create_or_update_security_question(username, question_number, question_text, answer):
    """Create or update a security question for a user"""
    existing = get_user_security_question(username, question_number)
    
    if existing:
        # Update existing question
        existing.question = question_text
        existing.set_answer(answer)
        return existing
    else:
        # Create new question
        new_question = SecurityQuestion(
            username=username,
            question_number=question_number,
            question=question_text
        )
        new_question.set_answer(answer)
        return new_question

# Predefined security questions for users to choose from
PREDEFINED_SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "In what city were you born?",
    "What was your mother's maiden name?",
    "What was the name of your first school?",
    "What was your childhood nickname?",
    "What is the name of the street you grew up on?",
    "What was the make and model of your first car?",
    "What is your favorite book?",
    "What is the name of the company where you had your first job?",
    "What is your favorite movie?",
    "What is the name of your favorite teacher?",
    "What is your favorite color?",
    "What is the name of your best friend from childhood?",
    "What is your favorite food?",
    "What is the name of the hospital where you were born?",
    "What is your favorite sport?",
    "What is the name of your favorite restaurant?",
    "What is your favorite holiday?",
    "What is the name of your favorite band or musician?",
    "What is your favorite season?"
] 