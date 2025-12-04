# Release Notes - Version 0.3.0

**Release Date:** December 4, 2025

## Major Features

### Organizational Chart System

This release introduces a comprehensive organizational chart management system that supports complex reporting relationships found in real-world organizations.

#### Key Features:
- **Supervisor Support**: Assign supervisors for indirect reporting (e.g., Manager → Supervisor → Employee)
- **Dotted-Line Relationships**: Support for secondary reporting relationships
- **Interactive Org Chart**: Beautiful D3.js-based visualization at `/admin/org-chart`
- **Enhanced Manager UI**: Improved manager assignment interface with relationship type options
- **User Detail Integration**: Manager and direct report information displayed on user detail pages

#### Use Cases:
- **Indirect Reports**: Perfect for structures like "Surveillance Manager → Supervisor → Operators"
- **Dotted-Line**: Support for relationships like "HR Director → General Manager" (secondary reporting)
- **Multi-Level Hierarchies**: Handle complex organizational structures with multiple management layers

### Automatic Database Migration in Updater

The updater now automatically handles database migrations, making in-place upgrades seamless:

- **Automatic Migration**: Runs `flask db upgrade` automatically after updates
- **Migration Failure Handling**: Clear error reporting and rollback options
- **Database Independence**: Each installation maintains its own database (not included in updates)
- **Cleanup**: Automatic removal of temp files and Python cache after updates

### GitHub Token Configuration

Secure GitHub token management for bug report integration:

- **Admin Settings Integration**: Configure GitHub token in Admin Settings
- **Secure Storage**: Token stored in encrypted credential storage (same as AD/Exchange passwords)
- **System-Level Token**: One token for the system (not per-user)
- **Clear Instructions**: Step-by-step guide for creating GitHub Personal Access Tokens

## Improvements

### Department Filtering
- Excluded "Racing Security" from department lists (not a department)
- Excluded "Vendor Logins" and variations from department lists
- Improved department extraction from OU structures

### Manager Assignment Display
- Manager information now visible on user detail pages
- Direct reports list for managers
- Links to manager and direct report profiles
- Visual indicators for relationship types

### Database Handling
- Database files properly excluded from git, backups, and updates
- Each installation maintains independent database
- Migration scripts included in updates and applied automatically
- First-time setup generates database for current version

## Technical Details

### Database Schema Changes
- Added `supervisor_username` and `supervisor_dn` fields to `UserDirectReport`
- Added `is_indirect_report` flag for indirect reporting
- Added `is_dotted_line` flag for dotted-line relationships
- Migration: `29d4432ec92b_add_supervisor_and_relationship_type_fields`

### New Routes
- `/admin/org-chart` - Interactive organizational chart visualization

### Updated Components
- `app/models.py` - Enhanced UserDirectReport model
- `app/updater.py` - Automatic migration and cleanup support
- `app/views.py` - Org chart route and enhanced manager management
- `app/templates/manage_managers.html` - Enhanced UI with supervisor support
- `app/templates/user_details.html` - Manager and direct reports display

## Upgrade Instructions

1. **Backup**: The updater will automatically create a backup
2. **Update**: Use the built-in updater or manually pull from Stable branch
3. **Migration**: Database migrations will run automatically
4. **Verify**: Check that the org chart is accessible at `/admin/org-chart`

## Breaking Changes

None - This is a backward-compatible release.

## Migration Notes

The database migration will automatically add new fields to the `user_direct_report` table. Existing manager assignments will continue to work, with new fields defaulting to `False` for `is_indirect_report` and `is_dotted_line`.

## Known Issues

None at this time.

## Contributors

- GEEKS Technologies LLC Development Team

