# First-Time Setup Verification Checklist

Use this checklist to verify that your GEEKS-AD-Plus installation is complete and functional.

## Pre-Installation

- [ ] Python 3.7+ installed (`python3 --version`)
- [ ] Git installed (`git --version`)
- [ ] Network connectivity to AD domain controller verified
- [ ] AD service account credentials available
- [ ] AD service account has necessary permissions

## Build Process

- [ ] Repository cloned successfully
- [ ] Correct branch checked out (Dev or Stable)
- [ ] Build script executed without errors
- [ ] Virtual environment created (`venv/` directory exists)
- [ ] All dependencies installed (check `requirements.txt`)
- [ ] Database initialized (`app/database.db` exists)
- [ ] `config.json` created from `config.example.json`
- [ ] Build log shows no critical errors

## Configuration Files

- [ ] `config.json` exists in project root
- [ ] `app/ad_config.json` will be created via web setup (or manually)

## Application Startup

- [ ] Application starts without errors
- [ ] Application accessible at http://localhost:5000
- [ ] Welcome page displays correctly
- [ ] No errors in console/logs

## Web-Based Setup

### Admin Account

- [ ] Admin registration page accessible
- [ ] First admin account created successfully
- [ ] Admin login works
- [ ] Admin dashboard accessible after login

### Active Directory Configuration

- [ ] Setup page accessible at `/setup`
- [ ] AD server address entered
- [ ] Port configured (389 for LDAP, 636 for LDAPS)
- [ ] Bind DN entered correctly
- [ ] Password entered
- [ ] Base DN entered correctly
- [ ] Optional OUs configured (if needed)
- [ ] Connection test successful
- [ ] Configuration saved successfully

## Functionality Tests

### Basic Functionality

- [ ] Home page displays after AD configuration
- [ ] AD connection test works from Settings
- [ ] User search works (Admin Dashboard → User Management)
- [ ] Users are displayed correctly
- [ ] No errors in application logs

### Admin Features

- [ ] Admin dashboard loads
- [ ] User search returns results
- [ ] User details view works
- [ ] AD statistics display correctly
- [ ] Audit logging works (check audit logs)

### Security

- [ ] Admin login required for protected pages
- [ ] Session management works (logout/login)
- [ ] Configuration files not accessible via web
- [ ] Passwords not displayed in logs

## Post-Setup Configuration (Optional)

- [ ] Admin groups configured (Settings → Admin Groups)
- [ ] Organization OUs configured (`app/ad_config.json`)
- [ ] Branding customized (`app/branding_config.json`)
- [ ] Exchange Server configured (if applicable)
- [ ] Systemd service configured (for production)

## Troubleshooting

If any item fails:

1. **Check logs**: `tail -f app/logs/geeks_ad_plus.log`
2. **Check build log**: `cat build.log`
3. **Verify configuration**: Check `config.json` and `app/ad_config.json`
4. **Test AD connection**: Use `ldapsearch` or similar tool
5. **Review documentation**: See [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md) troubleshooting section

## Common Issues

### Build Fails
- [ ] System dependencies installed (python3-dev, libldap2-dev, etc.)
- [ ] Virtual environment permissions correct
- [ ] Python version is 3.7+

### Application Won't Start
- [ ] Port 5000 not in use
- [ ] Database file permissions correct
- [ ] Configuration files exist and are readable

### AD Connection Fails
- [ ] AD server address correct
- [ ] Network connectivity verified (`ping AD_SERVER`)
- [ ] Port accessible (`telnet AD_SERVER 389`)
- [ ] Credentials correct
- [ ] Firewall rules allow connection

### Users Not Showing
- [ ] Base DN correct
- [ ] Users OU configured correctly (if specified)
- [ ] Service account has read permissions
- [ ] AD filters configured correctly

## Success Criteria

Your setup is complete when:

✅ Application starts without errors  
✅ Admin account created and login works  
✅ AD configuration saved and connection test passes  
✅ Users can be searched and displayed  
✅ Admin dashboard functions correctly  
✅ No critical errors in logs  

## Next Steps

After completing this checklist:

1. Review [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) for advanced configuration
2. Set up systemd service for production use
3. Configure firewall rules
4. Set up SSL/TLS for production
5. Configure backup procedures
6. Review security best practices

---

**Need Help?** See [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md) for detailed instructions or check the troubleshooting section.

