"""
Secure credential storage and management
Uses encrypted local storage to keep credentials out of git
"""
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

CREDENTIALS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.credentials.enc')
KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.credentials.key')

def _get_or_create_key():
    """Get or create encryption key"""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        # Generate a new key
        key = Fernet.generate_key()
        # Store key with restricted permissions
        os.umask(0o077)  # Restrict permissions
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        os.chmod(KEY_FILE, 0o600)  # Only owner can read/write
        return key

def _get_fernet():
    """Get Fernet cipher instance"""
    key = _get_or_create_key()
    return Fernet(key)

def save_credentials(credentials_dict):
    """
    Save credentials securely to encrypted file
    
    Args:
        credentials_dict: Dictionary with credential keys and values
    """
    try:
        fernet = _get_fernet()
        
        # Load existing credentials
        existing = load_credentials()
        existing.update(credentials_dict)
        
        # Encrypt and save
        encrypted_data = fernet.encrypt(json.dumps(existing).encode())
        
        os.umask(0o077)  # Restrict permissions
        with open(CREDENTIALS_FILE, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(CREDENTIALS_FILE, 0o600)  # Only owner can read/write
        
        return True
    except Exception as e:
        print(f"Error saving credentials: {e}")
        return False

def load_credentials():
    """
    Load credentials from encrypted file
    
    Returns:
        dict: Dictionary of credentials or empty dict if file doesn't exist
    """
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    
    try:
        fernet = _get_fernet()
        
        with open(CREDENTIALS_FILE, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return {}

def get_credential(key, default=None):
    """
    Get a specific credential
    
    Args:
        key: Credential key name
        default: Default value if not found
        
    Returns:
        str: Credential value or default
    """
    credentials = load_credentials()
    return credentials.get(key, default)

def set_credential(key, value):
    """
    Set a specific credential
    
    Args:
        key: Credential key name
        value: Credential value
    """
    return save_credentials({key: value})

def delete_credential(key):
    """
    Delete a specific credential
    
    Args:
        key: Credential key name
    """
    credentials = load_credentials()
    if key in credentials:
        del credentials[key]
        fernet = _get_fernet()
        encrypted_data = fernet.encrypt(json.dumps(credentials).encode())
        
        os.umask(0o077)
        with open(CREDENTIALS_FILE, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(CREDENTIALS_FILE, 0o600)
        return True
    return False

def migrate_from_config_files():
    """
    Migrate credentials from config files to secure storage
    This should be run once to move existing credentials
    """
    credentials = {}
    
    # Try to load from ad_config.json
    ad_config_path = os.path.join(os.path.dirname(__file__), 'ad_config.json')
    if os.path.exists(ad_config_path):
        try:
            with open(ad_config_path, 'r') as f:
                ad_config = json.load(f)
                if ad_config.get('ad_password'):
                    credentials['ad_password'] = ad_config['ad_password']
        except:
            pass
    
    # Try to load from exchange_config.json
    exchange_config_path = os.path.join(os.path.dirname(__file__), 'exchange_config.json')
    if os.path.exists(exchange_config_path):
        try:
            with open(exchange_config_path, 'r') as f:
                exchange_config = json.load(f)
                if exchange_config.get('password'):
                    credentials['exchange_password'] = exchange_config['password']
        except:
            pass
    
    # Try to load from config.json
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                if config.get('ad_bind_password'):
                    credentials['ad_bind_password'] = config['ad_bind_password']
                if config.get('secret_key'):
                    credentials['secret_key'] = config['secret_key']
        except:
            pass
    
    if credentials:
        save_credentials(credentials)
        print(f"Migrated {len(credentials)} credentials to secure storage")
        return True
    
    return False

