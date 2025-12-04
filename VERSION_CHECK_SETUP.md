# Version Check System Setup

The GEEKS-AD-Tools application now includes automatic version checking that monitors the GitHub repository for new releases and displays update notifications.

## Features

- **Automatic Version Checking**: Checks GitHub for the latest version from the stable branch
- **Update Notifications**: Displays a notification when a newer version is available
- **Caching**: Version checks are cached for 1 hour to reduce API calls
- **Global Display**: Version information is available on all pages
- **API Endpoint**: RESTful API for programmatic version checking

## Configuration

### GitHub Repository Settings

Edit `config.json` to configure the GitHub repository:

```json
{
  "github_repo": "GeeksTechnologies/GEEKS-AD-Tools",
  "github_branch": "stable"
}
```

**Configuration Options:**
- `github_repo`: GitHub repository in format `owner/repo` (e.g., `GeeksTechnologies/GEEKS-AD-Tools`)
- `github_branch`: Branch to check for version (default: `stable`, can be `main`, `master`, etc.)

### Environment Variables (Alternative)

You can also set these via environment variables:
- `GITHUB_REPO`: GitHub repository
- `GITHUB_BRANCH`: Branch name

## How It Works

1. **Version Source**: The system checks for the latest GitHub release first
2. **Fallback**: If no releases exist, it checks the `version.py` file in the specified branch
3. **Caching**: Results are cached for 1 hour to minimize API calls
4. **Display**: Version info appears in the bottom-right corner of all pages

## Adding Version Display to Templates

To add version information to any template, simply include the version component:

```html
<!-- At the end of your template, before </body> -->
{% include 'version_info.html' %}
```

The version information is automatically available via the context processor, so no additional variables need to be passed.

## API Endpoint

### Check Version

**Endpoint**: `/api/version/check`

**Method**: GET

**Authentication**: Required (login_required)

**Query Parameters**:
- `force` (optional): Set to `true` to bypass cache and force a fresh check

**Response**:
```json
{
  "success": true,
  "current_version": "0.1.0",
  "latest_version": "0.2.0",
  "update_available": true,
  "release_url": "https://github.com/owner/repo/releases/tag/v0.2.0",
  "release_notes": "Release notes...",
  "error": null,
  "cached": false
}
```

**Example Usage**:
```javascript
fetch('/api/version/check?force=true')
  .then(response => response.json())
  .then(data => {
    if (data.update_available) {
      console.log(`Update available: ${data.latest_version}`);
    }
  });
```

## Version Comparison

The system uses semantic versioning comparison:
- Versions are compared as tuples (e.g., "1.2.3" → (1, 2, 3))
- Pre-release versions (e.g., "1.2.3-beta") are handled gracefully
- String comparison is used as fallback if parsing fails

## Current Version

The current version is defined in `app/version.py`:

```python
__version__ = "0.1.0"
```

Update this file when releasing a new version.

## Troubleshooting

### Version Check Not Working

1. **Check GitHub Repository**: Verify `github_repo` in `config.json` is correct
2. **Check Branch**: Ensure `github_branch` exists and contains `app/version.py`
3. **Network Access**: Ensure the server can reach `api.github.com`
4. **API Rate Limits**: GitHub API has rate limits (60 requests/hour for unauthenticated requests)

### Caching Issues

- Force a refresh by calling `/api/version/check?force=true`
- Clear the in-memory cache by restarting the application
- Cache duration is 1 hour by default (configurable in `version_checker.py`)

### Display Issues

- Ensure `version_info.html` is included in templates
- Check browser console for JavaScript errors
- Verify Font Awesome icons are loaded (required for icons)

## Dependencies

The version checker requires:
- `requests` library (added to `requirements.txt`)
- Internet connectivity to GitHub API
- Flask context processor (already configured)

## Security Considerations

- Version checks are read-only operations
- No sensitive data is transmitted
- GitHub API calls are made server-side
- Results are cached to minimize external requests
- API endpoint requires authentication

## Future Enhancements

Potential improvements:
- Background job for periodic version checks
- Email notifications for updates
- Automatic update download (if implemented)
- Version history display
- Changelog integration

