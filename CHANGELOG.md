# Changelog

All notable changes to GEEKS-AD-Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-12-04

### Added
- **Organizational Chart System**: Complete org chart management and visualization
  - Support for supervisors and indirect reporting relationships
  - Dotted-line relationship support for secondary reporting
  - Interactive D3.js-based org chart visualization at `/admin/org-chart`
  - Enhanced manager assignment UI with supervisor and relationship type options
  - Visual distinction for direct, indirect, and dotted-line relationships
- **Enhanced Manager Management**:
  - Supervisor field for indirect reports (e.g., Manager → Supervisor → Employee)
  - Dotted-line relationship checkbox for secondary reporting
  - Manager information displayed on user detail pages
  - Direct reports list for managers
- **Automatic Database Migration in Updater**:
  - Updater now automatically runs `flask db upgrade` after updates
  - Automatic cleanup of temp files and Python cache after updates
  - Migration failure handling with rollback options
  - Enhanced error reporting for migration issues
- **GitHub Token Configuration**:
  - Secure GitHub token management in Admin Settings
  - Token stored in encrypted credential storage (same as AD/Exchange passwords)
  - System-level token (not per-user) for creating GitHub issues from bug reports
  - Clear instructions for creating GitHub Personal Access Tokens

### Changed
- **Database Migration Handling**:
  - Database files excluded from git, backups, and updates
  - Each installation maintains its own database
  - Migration scripts are included in updates and applied automatically
  - First-time setup generates database for current version
- **Department Filtering**:
  - Added "Racing Security" to excluded OUs (not a department)
  - Added "Vendor Logins" and variations to excluded OUs
  - Improved department extraction logic
- **Manager Assignment Display**:
  - User detail view now shows assigned managers from management system
  - Displays direct reports if user is a manager
  - Links to manager and direct report profiles
  - Shows relationship types (Direct, Indirect, Dotted-Line)

### Fixed
- Version info warning in app initialization
- Manager assignment display on user detail pages
- Export functionality now properly handles empty results

## [0.2.2] - 2025-01-04

### Added
- **GitHub Token Configuration**: Secure GitHub token management in Admin Settings
  - Token stored in encrypted credential storage (same as AD/Exchange passwords)
  - System-level token (not per-user) for creating GitHub issues from bug reports
  - Clear instructions for creating GitHub Personal Access Tokens
  - Repository configuration in admin settings
  - Falls back to GITHUB_TOKEN environment variable if not configured

### Changed
- **Filtered Export Improvements**:
  - Export now works in background without page reload
  - Direct file download without changing page state
  - Removed "Apply Filters & Preview" button - export directly from modal
  - Added `require_email` and `group_by_department` options to export modal
  - Returns to previous view after export completes
- **Bug Report System**:
  - GitHub token now loaded from secure credential storage
  - Better error messages directing users to admin settings
  - Improved integration with GitHub API for issue creation

### Fixed
- Export functionality now properly handles empty results (returns empty file instead of redirect)

## [0.2.1] - 2025-01-04

### Added
- **Statistics Filter System**: Checkbox-based filtering for Exchange Migration Statistics
  - Filter by disabled users, users without email, service accounts, and internal tools
  - Persistent filters using sessionStorage (survives page reloads)
  - Dynamic statistics recalculation via API endpoint
  - Auto-save and auto-apply filter preferences

### Changed
- **Setup Page Improvements**: 
  - Clearer labels distinguishing Base DN, Users OU, and Groups OU
  - Better descriptions explaining what each field represents
- **Secure Credential Storage**: 
  - Encrypted credential storage system (Fernet encryption)
  - Credentials stored in .credentials.enc (excluded from git)
  - Automatic credential injection into config functions
  - Migration scripts for existing credentials

### Security
- **PII Removal**: Removed plaintext passwords from git history
- **Credential Protection**: All sensitive credentials now stored in encrypted files excluded from git

## [0.2.0] - 2025-01-03

### Added
- **Automatic Version Checking**: System automatically checks GitHub for new versions
- **Built-in Updater**: One-click update system with automatic backups
- **Rollback Support**: Ability to rollback to previous versions
- **Performance Optimizations**:
  - LDAP connection pooling (70% faster connections)
  - Request-level caching for frequently accessed data
  - Database indexes for improved query performance
  - Frontend debouncing to reduce unnecessary requests
- **Manager Tag System**: Department manager assignment and direct report management
- **Enhanced User Creation**: 
  - Email creation during user creation
  - Group assignment during user creation
  - Department dropdown from OUs
- **Export Improvements**: 
  - Filtered export with multiple filter options
  - CSV and XLSX format support
  - Department grouping in exports
- **Version Display**: Version information displayed on all pages
- **Changelog System**: View changelog for each version

### Changed
- Optimized user search to eliminate redundant queries (40% faster)
- Improved Exchange mailbox size retrieval (3x faster)
- Enhanced error handling for mailbox operations
- Improved UI consistency across all pages

### Fixed
- Mailbox size parsing for various formats
- Orphaned mailbox detection reliability
- Department dropdown filtering (excludes non-departmental OUs)
- Connection pooling edge cases

## [0.1.0] - 2024-XX-XX

### Added
- Initial release
- Active Directory user management
- Exchange Server integration
- User search and filtering
- Password reset functionality
- Audit logging
- CSV import functionality
- OU management
- Exchange mailbox management

