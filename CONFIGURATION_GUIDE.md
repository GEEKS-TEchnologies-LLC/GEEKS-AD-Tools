# GEEKS-AD-Plus Configuration Guide

This guide explains how to configure the system for your organization's Active Directory structure.

## Configuration File: `app/ad_config.json`

The system uses a configuration file to adapt to different AD structures. The main configuration file is located at `app/ad_config.json`.

### Basic AD Configuration

```json
{
    "ad_server": "192.168.1.59",
    "ad_port": "389",
    "ad_bind_dn": "CN=Administrator,CN=Users,DC=yourdomain,DC=com",
    "ad_password": "YourPassword",
    "ad_base_dn": "DC=yourdomain,DC=com",
    "users_ou": "",
    "groups_ou": "",
    "admin_groups": [
        "Domain Admins",
        "IT Dept"
    ]
}
```

### Organization-Specific OU Configuration

The `organization_ous` section allows you to customize OU paths for your organization:

```json
{
    "organization_ous": {
        "primary_users_ou": "OU=Users,OU=Company",
        "disabled_users_ou": "OU=Disabled Users",
        "service_accounts_ou": "OU=Service Accounts",
        "internal_tools_ou": "OU=Internal Tools",
        "primary_users_label": "Company Users"
    }
}
```

#### Configuration Options:

- **`primary_users_ou`**: The main OU where your active users are located. This can be a partial path (e.g., `"OU=Users,OU=Company"`) or a full DN. The system will automatically append the base DN if not included.
  - Example: `"OU=Users,OU=Company"` → `"OU=Users,OU=Company,DC=yourdomain,DC=com"`

- **`disabled_users_ou`**: The OU where disabled users are stored. This OU is automatically excluded from user searches.
  - Example: `"OU=Disabled Users"` → `"OU=Disabled Users,DC=yourdomain,DC=com"`

- **`service_accounts_ou`**: The OU containing service accounts. These are tracked separately for migration planning.
  - Example: `"OU=Service Accounts"` → `"OU=Service Accounts,DC=yourdomain,DC=com"`

- **`internal_tools_ou`**: The OU containing internal tool accounts. These are tracked separately for migration planning.
  - Example: `"OU=Internal Tools"` → `"OU=Internal Tools,DC=yourdomain,DC=com"`

- **`primary_users_label`**: A friendly label used in the UI to refer to your primary users OU.
  - Example: `"Company Users"` or `"Main Users"`

### Example Configurations

#### Simple Flat Structure
```json
{
    "organization_ous": {
        "primary_users_ou": "",
        "disabled_users_ou": "OU=Disabled Users",
        "service_accounts_ou": "OU=Service Accounts",
        "internal_tools_ou": "OU=Internal Tools",
        "primary_users_label": "Users"
    }
}
```

#### Nested Structure
```json
{
    "organization_ous": {
        "primary_users_ou": "OU=Users,OU=Company",
        "disabled_users_ou": "OU=Disabled Users,OU=Company",
        "service_accounts_ou": "OU=Service Accounts,OU=Company",
        "internal_tools_ou": "OU=Internal Tools,OU=Company",
        "primary_users_label": "Company Users"
    }
}
```

#### Full DN Paths
```json
{
    "organization_ous": {
        "primary_users_ou": "OU=Users,OU=Company,DC=yourdomain,DC=com",
        "disabled_users_ou": "OU=Disabled Users,DC=yourdomain,DC=com",
        "service_accounts_ou": "OU=Service Accounts,DC=yourdomain,DC=com",
        "internal_tools_ou": "OU=Internal Tools,DC=yourdomain,DC=com",
        "primary_users_label": "Company Users"
    }
}
```

## Setting Up for a New Organization

1. **Copy the configuration file**:
   ```bash
   cp app/ad_config.json app/ad_config.json.backup
   ```

2. **Edit `app/ad_config.json`** with your organization's details:
   - Update `ad_server`, `ad_port`, `ad_bind_dn`, `ad_password`, and `ad_base_dn`
   - Configure the `organization_ous` section with your OU paths
   - Set the `primary_users_label` to match your organization

3. **Test the connection**:
   - Navigate to Settings → AD Configuration
   - Click "Test Connection" to verify connectivity

4. **Verify OU paths**:
   - Use the "User Search" page to verify users are being found correctly
   - Check that excluded OUs (disabled users, service accounts, etc.) are properly filtered

## Notes

- OU paths can be specified as partial paths (relative to base DN) or full DNs
- If an OU path doesn't include the base DN, it will be automatically appended
- The system gracefully handles missing OUs (e.g., if Service Accounts OU doesn't exist)
- All OU paths are case-insensitive for matching purposes
- The `primary_users_label` is only used for display purposes in the UI

## Troubleshooting

### Users Not Showing Up
- Verify `primary_users_ou` is correct
- Check that the bind DN has permissions to read from that OU
- Ensure the OU path matches your AD structure exactly

### Service Accounts/Internal Tools Not Counted
- Verify the OU paths in `organization_ous` match your AD structure
- Check that accounts in those OUs have email addresses (for Exchange migration planning)

### Disabled Users Still Showing
- Verify `disabled_users_ou` is correctly configured
- The system checks both the configured path and the string "OU=Disabled Users" in user DNs

