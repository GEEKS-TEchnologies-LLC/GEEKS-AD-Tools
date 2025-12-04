# Automatic Updater Guide

The GEEKS-AD-Tools application now includes a built-in automatic updater that can download and install new versions from GitHub.

## Features

- **Automatic Backup**: Creates a backup before updating
- **One-Click Updates**: Simple UI for installing updates
- **Rollback Support**: Restore to previous versions if needed
- **Version Checking**: Automatically detects available updates
- **Safe Installation**: Validates and installs updates safely

## Accessing the Updater

Navigate to **Admin Dashboard → System Updates** or go directly to `/admin/updates`

## How It Works

### Update Process

1. **Check for Updates**: The system checks GitHub for new releases
2. **Create Backup**: Before updating, a complete backup is created in the `backups/` directory
3. **Download Update**: Downloads the latest release or branch from GitHub
4. **Extract Files**: Extracts the downloaded archive
5. **Install Update**: Replaces application files with new versions
6. **Restart Required**: Manual restart needed after update

### Backup System

- Backups are stored in `backups/backup_YYYYMMDD_HHMMSS/`
- Each backup includes:
  - `app/` directory
  - `config.json`
  - `requirements.txt`
  - `app.py`
  - `database.db` (if exists)
  - `backup_metadata.json` (backup information)

### Rollback Process

If an update causes issues:

1. Go to **System Updates** page
2. Find the backup in the **Available Backups** section
3. Click **Rollback** button
4. Confirm the rollback
5. Restart the application

## Configuration

The updater uses the same GitHub configuration as the version checker:

```json
{
  "github_repo": "GeeksTechnologies/GEEKS-AD-Tools",
  "github_branch": "stable"
}
```

## Update Sources

The updater can download from:

1. **GitHub Releases** (preferred):
   - Downloads from the latest release
   - Includes release notes
   - More reliable versioning

2. **GitHub Branch** (fallback):
   - Downloads source code from specified branch
   - Used if no releases are available
   - Extracts from branch zip archive

## API Endpoints

### Check for Updates
```
GET /api/updates/check
```
Returns update availability information.

### Perform Update
```
POST /api/updates/perform
Body: { "version": "optional_version" }
```
Downloads and installs the update.

### Rollback
```
POST /api/updates/rollback
Body: { "backup_dir": "/path/to/backup" }
```
Restores from a backup.

### Get Backups
```
GET /api/updates/backups
```
Returns list of available backups.

## Safety Features

1. **Automatic Backups**: Always creates backup before updating
2. **Validation**: Checks file integrity during installation
3. **Error Handling**: Rolls back automatically on critical errors
4. **Audit Logging**: All update actions are logged

## Manual Update Process

If you prefer to update manually:

1. **Create Backup**:
   ```bash
   cp -r /path/to/GEEKS-AD-Tools /path/to/backup
   ```

2. **Download Update**:
   ```bash
   wget https://github.com/owner/repo/archive/refs/heads/stable.zip
   unzip stable.zip
   ```

3. **Install**:
   ```bash
   cp -r repo-stable/app /path/to/GEEKS-AD-Tools/
   cp repo-stable/app.py /path/to/GEEKS-AD-Tools/
   cp repo-stable/requirements.txt /path/to/GEEKS-AD-Tools/
   ```

4. **Update Dependencies**:
   ```bash
   cd /path/to/GEEKS-AD-Tools
   source venv/bin/activate
   pip install -r requirements.txt
   ```

5. **Restart**:
   ```bash
   # Restart your service/systemd service
   sudo systemctl restart geeks-ad-plus
   ```

## Troubleshooting

### Update Fails

1. **Check Logs**: Review application logs for errors
2. **Verify Backup**: Ensure backup was created successfully
3. **Check Permissions**: Ensure application has write permissions
4. **Network Issues**: Verify GitHub is accessible
5. **Rollback**: Use rollback feature to restore previous version

### Backup Not Found

- Backups are stored in `backups/` directory
- Check file permissions
- Verify disk space is available

### Update Installed But Not Working

1. **Restart Application**: Updates require restart
2. **Check Dependencies**: Run `pip install -r requirements.txt`
3. **Verify Files**: Check that files were updated correctly
4. **Rollback**: If issues persist, rollback to previous version

## Best Practices

1. **Test Updates**: Test updates in a development environment first
2. **Backup Database**: Always backup database before major updates
3. **Review Release Notes**: Check release notes for breaking changes
4. **Schedule Updates**: Perform updates during maintenance windows
5. **Monitor After Update**: Watch logs after updating

## Security Considerations

- Updates are downloaded from GitHub (verify repository)
- All update actions require admin authentication
- Backups may contain sensitive data (secure backup storage)
- Update process runs with application permissions

## Limitations

- **Manual Restart Required**: Application must be restarted after update
- **Database Migrations**: Database schema changes may require manual migration
- **Configuration Changes**: `config.json` is not overwritten (preserved)
- **Custom Files**: Custom files outside standard structure may need manual update

## Future Enhancements

Potential improvements:
- Automatic restart after update
- Database migration automation
- Update scheduling
- Email notifications for updates
- Update history tracking
- Delta updates (only changed files)

