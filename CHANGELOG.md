# Changelog

All notable changes to GEEKS-AD-Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

