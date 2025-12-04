# Changelog

All notable changes to GEEKS-AD-Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

