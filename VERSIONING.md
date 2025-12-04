# Versioning Scheme

GEEKS-AD-Tools uses a custom versioning scheme:

## Format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Major version number (e.g., 0, 1, 2)
- **MINOR**: Minor version number (e.g., 3, 4, 5) - incremented for major feature changes
- **PATCH**: Patch version (01-99) - incremented for minor updates, bug fixes, and small improvements

## Versioning Rules

### Minor Updates (Patch Version: 01-99)
- Bug fixes
- Small feature additions
- Performance improvements
- UI enhancements
- Documentation updates
- Security patches

**Examples:**
- `0.3.01` → `0.3.02` (bug fix)
- `0.3.15` → `0.3.16` (small feature)
- `0.3.99` → `0.4.01` (next major change)

### Major Changes (Minor Version Increment)
- New major features
- Significant architectural changes
- Breaking changes (if any)
- Major UI overhauls
- New system integrations

**Examples:**
- `0.3.99` → `0.4.01` (new major feature)
- `0.4.50` → `0.5.01` (significant change)
- `0.5.99` → `0.6.01` (major update)

## Version Comparison

The version checker compares versions using semantic versioning principles:
- `0.3.01` < `0.3.02` (patch increment)
- `0.3.99` < `0.4.01` (minor increment)
- `0.4.01` < `0.5.01` (minor increment)

## Current Version

See `app/version.py` for the current version number.

## Changelog

All version changes are documented in `CHANGELOG.md` following the format:
- `[MAJOR.MINOR.PATCH]` - Date
  - Added/Changed/Fixed sections

