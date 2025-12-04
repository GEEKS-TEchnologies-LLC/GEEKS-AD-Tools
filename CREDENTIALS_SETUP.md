# Secure Credential Management

GEEKS-AD-Tools now uses encrypted credential storage to keep passwords out of git while maintaining system functionality.

## How It Works

- **Encrypted Storage**: Credentials are stored in `.credentials.enc` (encrypted with Fernet)
- **Key File**: Encryption key stored in `.credentials.key` (restricted permissions)
- **Git Exclusion**: Both files are in `.gitignore` and never committed
- **Automatic Injection**: Application automatically loads credentials from secure storage

## Setting Up Credentials

### Option 1: Quick Restore (After Password Removal)

If you just removed passwords and need to restore them:

```bash
python3 restore_credentials.py
```

This will restore the known passwords to secure storage.

### Option 2: Interactive Setup

For new installations or to update credentials:

```bash
python3 setup_credentials.py
```

Follow the prompts to enter:
- AD password
- Exchange password  
- AD bind password (if different)
- Flask secret key

### Option 3: Programmatic Setup

```python
from app.credentials import save_credentials

save_credentials({
    'ad_password': 'your_ad_password',
    'exchange_password': 'your_exchange_password',
    'ad_bind_password': 'your_bind_password',  # Optional
    'secret_key': 'your_secret_key'  # Optional
})
```

## File Structure

```
GEEKS-AD-Tools/
├── .credentials.enc      # Encrypted credentials (NEVER commit)
├── .credentials.key     # Encryption key (NEVER commit)
├── app/
│   ├── ad_config.json    # Non-sensitive AD config (password removed)
│   └── exchange_config.json  # Non-sensitive Exchange config (password removed)
└── config.json           # Non-sensitive config (passwords removed)
```

## Security Features

1. **Encryption**: All credentials encrypted with Fernet (AES-128)
2. **File Permissions**: Credential files set to 600 (owner read/write only)
3. **Git Exclusion**: Files automatically excluded from version control
4. **Automatic Loading**: Application transparently loads credentials

## Migration

When upgrading from a version with passwords in config files:

1. The system will automatically migrate credentials on first run
2. Or run: `python3 setup_credentials.py` to migrate manually
3. Old config files can be cleaned (passwords already removed)

## Troubleshooting

### System Not Working After Password Removal

1. Run `python3 restore_credentials.py` to restore credentials
2. Or use `setup_credentials.py` to enter new credentials
3. Restart the application

### Credentials Not Loading

1. Check file permissions: `ls -la .credentials.*`
2. Verify files exist: `ls .credentials.enc .credentials.key`
3. Check application logs for credential loading errors
4. Re-run setup: `python3 setup_credentials.py`

### Changing Passwords

1. Update via UI (passwords saved securely automatically)
2. Or run: `python3 setup_credentials.py`
3. Or programmatically update via credentials module

## Best Practices

1. **Backup Credential Files**: Keep `.credentials.enc` and `.credentials.key` in secure backup
2. **Rotate Passwords**: Change passwords regularly
3. **Access Control**: Limit who has access to credential files
4. **Never Commit**: Double-check `.gitignore` before committing
5. **Separate Environments**: Use different credentials for dev/staging/prod

## API Usage

```python
from app.credentials import get_credential, set_credential, save_credentials

# Get a credential
password = get_credential('ad_password')

# Set a credential
set_credential('ad_password', 'new_password')

# Save multiple credentials
save_credentials({
    'ad_password': 'password1',
    'exchange_password': 'password2'
})
```

