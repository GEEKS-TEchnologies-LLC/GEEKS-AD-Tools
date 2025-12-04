import subprocess
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
import re
import time
import winrm

logger = logging.getLogger(__name__)

class ExchangeManager:
    def __init__(self, exchange_server: str, username: str, password: str, domain: str = None):
        """
        Initialize Exchange Manager for Exchange 2019
        
        Args:
            exchange_server: IP or hostname of Exchange server (e.g., 192.168.16.35)
            username: Username for PowerShell remoting
            password: Password for PowerShell remoting
            domain: Domain name (optional, will use username if not provided)
        """
        self.exchange_server = exchange_server
        self.password = password
        
        # Handle username format - could be "user@domain.com" or "domain\\user" or just "user"
        if '@' in username:
            # Username is in email format, extract username and domain
            self.username = username.split('@')[0]
            self.domain = domain or username.split('@')[1]
        elif '\\' in username:
            # Username is in domain\user format
            parts = username.split('\\', 1)
            self.domain = parts[0]
            self.username = parts[1]
        else:
            # Just username, use provided domain
            self.username = username
            self.domain = domain or 'example'
        
    def _run_powershell_command(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute PowerShell command on Exchange server via WinRM
        
        Args:
            command: PowerShell command to execute
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            # Create WinRM session
            session = winrm.Session(
                f'http://{self.exchange_server}:5985/wsman',
                auth=(f'{self.domain}\\{self.username}', self.password),
                transport='ntlm'
            )
            
            # Exchange Management Shell initialization must be included with each command
            # Exchange cmdlets need explicit credential context - use New-PSSession with Exchange endpoint
            username_with_domain = f'{self.domain}\\{self.username}'
            
            # Minimize command - use compact syntax to avoid "command line too long" error
            # Wrap Remove-PSSession in try-catch to avoid failures when session is already closed
            # Suppress progress messages from Import-PSSession by redirecting to $null
            # CLIXML progress messages are informational, not errors
            full_command = f"$p='{self.password}';$u='{username_with_domain}';$h='{self.exchange_server}';$c=[System.Management.Automation.PSCredential]::new($u,(ConvertTo-SecureString -AsPlainText -String $p -Force));[System.Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};$so=New-PSSessionOption -SkipCACheck -SkipCNCheck;$ProgressPreference='SilentlyContinue';try{{$s=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri \"https://$h/PowerShell/\" -Credential $c -Authentication Basic -SessionOption $so -AllowRedirection -ErrorAction Stop}}catch{{try{{$s=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri \"https://$h/PowerShell/\" -Credential $c -Authentication Kerberos -SessionOption $so -AllowRedirection -ErrorAction Stop}}catch{{throw \"Failed: $_\"}}}};Import-PSSession $s -DisableNameChecking -AllowClobber|Out-Null;$r={command};try{{Remove-PSSession $s -EA SilentlyContinue}}catch{{}};$r"
            
            # Execute the combined command
            result = session.run_ps(full_command)
            
            # Decode output
            stdout = result.std_out.decode('utf-8', errors='ignore') if result.std_out else ''
            stderr = result.std_err.decode('utf-8', errors='ignore') if result.std_err else ''
            
            # Filter out CLIXML progress messages from stderr (these are informational, not errors)
            # CLIXML messages start with '#< CLIXML'
            if stderr and stderr.strip().startswith('#< CLIXML'):
                # This is just progress output from Import-PSSession, not an actual error
                # Check if we have valid output in stdout
                if stdout.strip():
                    # Try to parse JSON to verify we got valid data
                    try:
                        json.loads(stdout.strip())
                        # Valid JSON found, treat as success
                        return True, stdout, ""
                    except json.JSONDecodeError:
                        # Not JSON, but still might be valid text output
                        # Check if it looks like an error message
                        if 'error' not in stdout.lower() and 'exception' not in stdout.lower():
                            return True, stdout, ""
                # If no stdout or invalid JSON, check if stderr contains actual errors
                # CLIXML progress messages don't contain actual error text
                if 'error' not in stderr.lower() and 'exception' not in stderr.lower() and 'failed' not in stderr.lower():
                    # Just progress messages, treat as success if we have any output
                    return True, stdout, ""
            
            # Check if we have valid JSON output despite non-zero status code
            # (This handles cases where Remove-PSSession cleanup failed but data was retrieved)
            if stdout.strip():
                try:
                    json.loads(stdout.strip())
                    # Valid JSON found, treat as success
                    return True, stdout, stderr
                except json.JSONDecodeError:
                    pass
            
            if result.status_code == 0:
                return True, stdout, stderr
            else:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"PowerShell command failed with status {result.status_code}")
                logger.error(f"Stdout (first 1000 chars): {stdout[:1000] if stdout else 'empty'}")
                logger.error(f"Stderr (first 1000 chars): {stderr[:1000] if stderr else 'empty'}")
                logger.error(f"Command: {command[:500]}...")  # Log first 500 chars of command
                logger.debug(f"Full traceback: {error_trace}")
                return False, stdout, stderr
                
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error running PowerShell command: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Full traceback: {error_trace}")
            logger.error(f"Command: {command[:500] if 'command' in locals() else 'N/A'}...")
            return False, "", str(e)
    
    def get_mailbox_sizes(self, user_emails: List[str]) -> Dict[str, Dict]:
        """
        Get mailbox sizes for a list of users
        
        Args:
            user_emails: List of email addresses
            
        Returns:
            Dictionary mapping email to mailbox info
        """
        if not user_emails:
            return {}
        
        # Process in batches to avoid "command line too long" error
        # Use larger batches to reduce total processing time and avoid timeouts
        # Process 10 emails at a time - this reduces batches from 26 to ~8, cutting time by ~3x
        batch_size = 10
        all_results = {}
        
        for i in range(0, len(user_emails), batch_size):
            batch_emails = user_emails[i:i+batch_size]
            logger.info(f"Processing mailbox batch {i//batch_size + 1} of {(len(user_emails)-1)//batch_size + 1} ({len(batch_emails)} emails)")
            
            batch_results = self._get_mailbox_sizes_batch(batch_emails)
            all_results.update(batch_results)
        
        return all_results
    
    def _get_mailbox_sizes_batch(self, user_emails: List[str]) -> Dict[str, Dict]:
        """
        Get mailbox sizes for a batch of users (internal method)
        
        Args:
            user_emails: List of email addresses (should be small batch, e.g., 20 or less)
            
        Returns:
            Dictionary mapping email to mailbox info
        """
        if not user_emails:
            return {}
            
        # Create PowerShell command to get mailbox sizes
        # Handle deserialized ByteQuantifiedSize objects which become strings like "30.94 GB (33,221,930,407 bytes)"
        email_list = "','".join(user_emails)
        # Use % formatting to avoid brace escaping issues with format()
        command = "$r=@();foreach($x in @('%s')){try{$m=Get-Mailbox -Identity $x -EA Stop;$s=Get-MailboxStatistics -Identity $m.Identity -EA Stop;$b=0;if($s.TotalItemSize){$ts=$s.TotalItemSize.ToString();if($ts -match '\\((\\d+(?:,\\d+)*)\\s+bytes\\)'){$b=[int64]($matches[1] -replace ',','')}elseif($ts -match '([\\d.]+)\\s*(GB|MB|KB)'){$v=[double]$matches[1];$u=$matches[2].ToUpper();switch($u){'GB'{$b=[int64]($v*1GB)}'MB'{$b=[int64]($v*1MB)}'KB'{$b=[int64]($v*1KB)}}}};$r+=@{Email=$x;PrimarySmtpAddress=$m.PrimarySmtpAddress;DisplayName=$m.DisplayName;TotalItemSize=$b;TotalItemCount=$s.ItemCount;LastLogonTime=$s.LastLogonTime;Database=$m.Database};}catch{$r+=@{Email=$x;Error=$_.Exception.Message}}};$r|ConvertTo-Json -Depth 3" % email_list
        logger.debug(f"Requesting mailbox sizes for batch of {len(user_emails)} emails: {user_emails[:3]}...")
        success, stdout, stderr = self._run_powershell_command(command)
        
        logger.debug(f"PowerShell command result: success={success}, stdout_length={len(stdout) if stdout else 0}, stderr_length={len(stderr) if stderr else 0}")
        
        # Check if we have valid JSON output, even if command returned non-zero status
        # (This handles cases where Remove-PSSession cleanup failed but data was retrieved)
        has_valid_output = False
        if stdout.strip():
            try:
                # Try to parse JSON to see if we got valid data
                test_data = json.loads(stdout.strip())
                has_valid_output = True
            except json.JSONDecodeError:
                has_valid_output = False
        
        if (success or has_valid_output) and stdout.strip():
            try:
                # Parse JSON output
                data = json.loads(stdout.strip())
                # Convert to case-insensitive dictionary (lowercase keys)
                # Use both Email and PrimarySmtpAddress for matching
                result = {}
                if isinstance(data, list):
                    for item in data:
                        # Skip items with errors
                        if item.get('Error'):
                            logger.warning(f"Mailbox lookup error for {item.get('Email', 'unknown')}: {item.get('Error')}")
                            continue
                        # Try Email first, then PrimarySmtpAddress
                        email_key = (item.get('Email') or item.get('PrimarySmtpAddress') or '').lower()
                        if email_key:
                            result[email_key] = item
                            logger.debug(f"Found mailbox for {email_key}: {item.get('TotalItemSize', 0)} bytes")
                else:
                    if data.get('Error'):
                        logger.warning(f"Mailbox lookup error: {data.get('Error')}")
                    else:
                        email_key = (data.get('Email') or data.get('PrimarySmtpAddress') or '').lower()
                        if email_key:
                            result[email_key] = data
                            logger.debug(f"Found mailbox for {email_key}: {data.get('TotalItemSize', 0)} bytes")
                logger.info(f"Successfully retrieved mailbox sizes for {len(result)} mailboxes out of {len(user_emails)} requested. Keys: {list(result.keys())[:5]}")
                if len(result) < len(user_emails):
                    missing = set([e.lower() for e in user_emails]) - set(result.keys())
                    logger.warning(f"Missing mailboxes for: {list(missing)[:5]}")
                return result
            except json.JSONDecodeError as e:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"Failed to parse JSON output: {e}")
                logger.error(f"JSON decode error type: {type(e).__name__}")
                logger.error(f"Stdout (first 2000 chars): {stdout[:2000]}")
                logger.error(f"Stderr (first 2000 chars): {stderr[:2000] if stderr else 'empty'}")
                logger.error(f"Full traceback: {error_trace}")
                logger.error(f"Email batch: {user_emails[:10] if 'user_emails' in locals() else 'N/A'}")
                return {}
        else:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"PowerShell command failed. Status: {success}")
            logger.error(f"Stdout (first 2000 chars): {stdout[:2000] if stdout else 'empty'}")
            logger.error(f"Stderr (first 2000 chars): {stderr[:2000] if stderr else 'empty'}")
            logger.error(f"Full traceback: {error_trace}")
            logger.error(f"Email batch: {user_emails[:10] if 'user_emails' in locals() else 'N/A'}")
            return {}
    
    def cleanup_mailbox(self, email: str, cleanup_options: Dict) -> Tuple[bool, str]:
        """
        Perform mailbox cleanup tasks
        
        Args:
            email: Email address of mailbox to clean
            cleanup_options: Dictionary with cleanup options
            
        Returns:
            Tuple of (success, message)
        """
        commands = []
        
        # Empty deleted items
        if cleanup_options.get('empty_deleted_items', False):
            commands.append(f"Search-Mailbox -Identity '{email}' -SearchQuery 'kind:deleteditems' -DeleteContent -Force")
        
        # Clean sent items older than X days
        if cleanup_options.get('clean_sent_items_days'):
            days = cleanup_options['clean_sent_items_days']
            commands.append(f"Search-Mailbox -Identity '{email}' -SearchQuery 'kind:sentitems AND sent:<{days} days ago' -DeleteContent -Force")
        
        # Clean items older than X days
        if cleanup_options.get('clean_old_items_days'):
            days = cleanup_options['clean_old_items_days']
            commands.append(f"Search-Mailbox -Identity '{email}' -SearchQuery 'received:<{days} days ago' -DeleteContent -Force")
        
        if not commands:
            return False, "No cleanup options specified"
        
        # Execute cleanup commands
        for cmd in commands:
            success, stdout, stderr = self._run_powershell_command(cmd)
            if not success:
                return False, f"Cleanup failed: {stderr}"
        
        return True, "Mailbox cleanup completed successfully"
    
    def create_mailbox(self, email: str, display_name: str, database: str = None) -> Tuple[bool, str]:
        """
        Create a new mailbox for a user
        
        Args:
            email: Email address for the mailbox
            display_name: Display name for the user
            database: Database name (optional, will use default)
            
        Returns:
            Tuple of (success, message)
        """
        # Extract username from email
        username = email.split('@')[0]
        
        # Create mailbox command
        if database:
            cmd = f"Enable-Mailbox -Identity '{username}' -Database '{database}'"
        else:
            cmd = f"Enable-Mailbox -Identity '{username}'"
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success:
            return True, f"Mailbox created successfully for {email}"
        else:
            return False, f"Failed to create mailbox: {stderr}"
    
    def set_mailbox_quota(self, email: str, quota_mb: int) -> Tuple[bool, str]:
        """
        Set mailbox quota
        
        Args:
            email: Email address
            quota_mb: Quota in MB
            
        Returns:
            Tuple of (success, message)
        """
        quota_size = f"{quota_mb}MB"
        cmd = f"Set-Mailbox -Identity '{email}' -ProhibitSendQuota '{quota_size}' -ProhibitSendReceiveQuota '{quota_size}' -IssueWarningQuota '{quota_size * 0.8}MB'"
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success:
            return True, f"Mailbox quota set to {quota_mb}MB for {email}"
        else:
            return False, f"Failed to set quota: {stderr}"
    
    def get_database_info(self) -> List[Dict]:
        """
        Get information about Exchange databases
        
        Returns:
            List of database information
        """
        cmd = "Get-MailboxDatabase | Select-Object Name, Server, DatabaseSize, Mounted | ConvertTo-Json -Depth 3"
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success and stdout.strip():
            try:
                data = json.loads(stdout.strip())
                if isinstance(data, list):
                    return data
                else:
                    return [data]
            except json.JSONDecodeError:
                return []
        else:
            return []
    
    def get_all_mailboxes(self) -> List[Dict]:
        """
        Get all mailboxes from Exchange server
        
        Returns:
            List of mailbox information
        """
        cmd = """
        Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, PrimarySmtpAddress, 
        Database, RecipientType, RecipientTypeDetails | ConvertTo-Json -Depth 3
        """
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success and stdout.strip():
            try:
                data = json.loads(stdout.strip())
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return [data]
                else:
                    logger.warning(f"Unexpected data type from get_all_mailboxes: {type(data)}")
                    return []
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse mailbox data: {e}")
                logger.error(f"Stdout (first 500 chars): {stdout[:500] if stdout else 'empty'}")
                logger.error(f"Stderr (first 500 chars): {stderr[:500] if stderr else 'empty'}")
                return []
        else:
            logger.error(f"Failed to get mailboxes. Success: {success}")
            logger.error(f"Stdout (first 500 chars): {stdout[:500] if stdout else 'empty'}")
            logger.error(f"Stderr (first 500 chars): {stderr[:500] if stderr else 'empty'}")
            return []
    
    def get_mailbox_stats(self, email_addresses: List[str]) -> Dict[str, Dict]:
        """
        Get mailbox statistics (size, item count, last logon) for specific mailboxes
        
        Args:
            email_addresses: List of email addresses to get stats for
            
        Returns:
            Dictionary mapping email (lowercase) to mailbox stats
        """
        if not email_addresses:
            return {}
        
        stats = {}
        
        # Process in batches to avoid command line length limits
        batch_size = 10
        for i in range(0, len(email_addresses), batch_size):
            batch = email_addresses[i:i+batch_size]
            email_list = "','".join(batch)
            
            cmd = f"""
            $emails = @('{email_list}');
            $stats = @{{}};
            foreach ($email in $emails) {{
                try {{
                    $mb = Get-MailboxStatistics -Identity $email -ErrorAction SilentlyContinue;
                    if ($mb) {{
                        $stats[$email] = @{{
                            TotalItemSize = if ($mb.TotalItemSize) {{ $mb.TotalItemSize.ToString() }} else {{ '0 B' }};
                            ItemCount = $mb.ItemCount;
                            LastLogonTime = if ($mb.LastLogonTime) {{ $mb.LastLogonTime.ToString('yyyy-MM-ddTHH:mm:ss') }} else {{ $null }};
                            DisplayName = $mb.DisplayName;
                            PrimarySmtpAddress = $mb.PrimarySmtpAddress
                        }}
                    }}
                }} catch {{
                    $stats[$email] = @{{}}
                }}
            }};
            $stats | ConvertTo-Json -Depth 3
            """
            
            success, stdout, stderr = self._run_powershell_command(cmd)
            
            if success and stdout.strip():
                try:
                    batch_stats = json.loads(stdout.strip())
                    if isinstance(batch_stats, dict):
                        for email, stat_data in batch_stats.items():
                            if stat_data:
                                # Parse TotalItemSize from string format
                                total_size = stat_data.get('TotalItemSize', '0 B')
                                if isinstance(total_size, str):
                                    # Parse formats like "10 GB (10737418240 bytes)" or "500 MB"
                                    try:
                                        # Try to extract bytes from format like "X GB (Y bytes)"
                                        if '(' in total_size and 'bytes' in total_size:
                                            bytes_str = total_size.split('(')[1].split('bytes')[0].strip()
                                            stat_data['TotalItemSize'] = int(bytes_str)
                                        else:
                                            # Fallback: try to parse size string
                                            stat_data['TotalItemSize'] = self._parse_size_string(total_size)
                                    except:
                                        stat_data['TotalItemSize'] = 0
                                stats[email.lower()] = stat_data
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse mailbox stats batch: {e}")
                    continue
        
        return stats
    
    def _parse_size_string(self, size_str: str) -> int:
        """Parse size string like '10 GB' or '500 MB' to bytes"""
        try:
            size_str = size_str.strip().upper()
            if 'GB' in size_str:
                value = float(size_str.replace('GB', '').strip())
                return int(value * 1024 * 1024 * 1024)
            elif 'MB' in size_str:
                value = float(size_str.replace('MB', '').strip())
                return int(value * 1024 * 1024)
            elif 'KB' in size_str:
                value = float(size_str.replace('KB', '').strip())
                return int(value * 1024)
            else:
                # Try to extract just the number
                import re
                match = re.search(r'[\d.]+', size_str)
                if match:
                    return int(float(match.group()) * 1024)  # Assume KB if no unit
        except:
            pass
        return 0
    
    def find_orphaned_mailboxes(self, active_emails: List[str]) -> Dict[str, List[Dict]]:
        """
        Find mailboxes that exist in Exchange but don't have corresponding active users
        
        Args:
            active_emails: List of email addresses that should have mailboxes
            
        Returns:
            Dictionary with 'orphaned' and 'missing' mailboxes
        """
        try:
            all_mailboxes = self.get_all_mailboxes()
        except Exception as e:
            logger.error(f"Error getting all mailboxes: {e}")
            return {'orphaned': [], 'missing': []}
        
        # Convert all active emails to lowercase for case-insensitive comparison
        active_email_set = set(email.lower() for email in active_emails if email)
        
        orphaned = []
        missing = []
        
        # Find mailboxes that exist but shouldn't (orphaned mailboxes)
        orphaned_emails = []
        for mailbox in all_mailboxes:
            email = (mailbox.get('PrimarySmtpAddress') or '').lower()
            if email and email not in active_email_set:
                orphaned.append(mailbox)
                orphaned_emails.append(mailbox.get('PrimarySmtpAddress'))
        
        # Get mailbox statistics for orphaned mailboxes (size, item count, last logon)
        if orphaned_emails:
            logger.info(f"Fetching mailbox statistics for {len(orphaned_emails)} orphaned mailboxes...")
            try:
                stats = self.get_mailbox_stats(orphaned_emails)
                
                # Merge stats into orphaned mailboxes
                for mailbox in orphaned:
                    email = (mailbox.get('PrimarySmtpAddress') or '').lower()
                    if email in stats:
                        mailbox.update(stats[email])
            except Exception as e:
                logger.error(f"Error getting mailbox stats for orphaned mailboxes: {e}")
        
        # Find emails that should have mailboxes but don't (missing mailboxes)
        all_mailbox_emails = set((mb.get('PrimarySmtpAddress') or '').lower() for mb in all_mailboxes if mb.get('PrimarySmtpAddress'))
        for email in active_emails:
            if not email:
                continue
            email_lower = email.lower()
            if email_lower not in all_mailbox_emails:
                missing.append({'PrimarySmtpAddress': email, 'DisplayName': 'Missing Mailbox'})
        
        logger.info(f"Found {len(orphaned)} orphaned mailboxes and {len(missing)} missing mailboxes")
        return {
            'orphaned': orphaned,
            'missing': missing
        }
    
    def archive_mailbox(self, email: str, archive_path: str, use_local_temp: bool = False) -> Tuple[bool, str]:
        """
        Export a mailbox to PST file
        
        Args:
            email: Email address of the mailbox to export
            archive_path: Path where PST file will be created. If use_local_temp is True, this is a local Exchange server path.
                         Otherwise, this is a network share path accessible from Exchange server.
            use_local_temp: If True, use a local temp directory on Exchange server. If False, use network share.
            
        Returns:
            Tuple of (success, message/error)
        """
        try:
            logger.info(f"Starting archive for mailbox: {email} to path: {archive_path} (local_temp={use_local_temp})")
            
            # Use New-MailboxExportRequest to export mailbox to PST
            if use_local_temp:
                # Use local temp directory on Exchange server
                # archive_path should be something like "C:\\Temp\\ExchangeArchives" or just use system temp
                if not archive_path or archive_path == '':
                    # Use system temp directory - expand environment variable first
                    expand_cmd = "$tempPath = [System.IO.Path]::Combine($env:TEMP, 'ExchangeArchives'); if(-not(Test-Path $tempPath)){New-Item -ItemType Directory -Path $tempPath -Force | Out-Null}; $tempPath"
                    success, stdout, stderr = self._run_powershell_command(expand_cmd)
                    if success and stdout:
                        archive_path = stdout.strip()
                        logger.info(f"Using temp directory: {archive_path}")
                    else:
                        # Fallback to a hardcoded path
                        archive_path = 'C:\\Temp\\ExchangeArchives'
                        logger.warning(f"Failed to get temp path, using fallback: {archive_path}")
                        create_dir_cmd = f"if(-not(Test-Path '{archive_path}')){{New-Item -ItemType Directory -Path '{archive_path}' -Force | Out-Null}}"
                        self._run_powershell_command(create_dir_cmd)
                else:
                    # Ensure directory exists if path was provided
                    create_dir_cmd = f"if(-not(Test-Path '{archive_path}')){{New-Item -ItemType Directory -Path '{archive_path}' -Force | Out-Null}}"
                    self._run_powershell_command(create_dir_cmd)
                pst_filename = f"{email.replace('@', '_at_').replace('.', '_')}.pst"
                pst_path = f"{archive_path}\\{pst_filename}"
            else:
                # Use network share path (original behavior)
                pst_filename = f"{email.replace('@', '_at_').replace('.', '_')}.pst"
                pst_path = f"{archive_path}\\{pst_filename}"
            
            logger.debug(f"PST file will be: {pst_path}")
            
            # Create export request
            command = f"$er=New-MailboxExportRequest -Mailbox '{email}' -FilePath '{pst_path}' -ErrorAction Stop;Start-Sleep -Seconds 2;Get-MailboxExportRequest -Identity $er.Identity | Select-Object Identity,Status,RequestQueue | ConvertTo-Json -Depth 2"
            
            logger.debug(f"Executing PowerShell export command for {email}")
            success, stdout, stderr = self._run_powershell_command(command)
            
            logger.info(f"PowerShell command result for {email}: success={success}, stdout_length={len(stdout) if stdout else 0}, stderr_length={len(stderr) if stderr else 0}")
            
            if stdout:
                logger.debug(f"PowerShell stdout for {email}: {stdout[:500]}")  # First 500 chars
            if stderr:
                logger.debug(f"PowerShell stderr for {email}: {stderr[:500]}")  # First 500 chars
            
            if success:
                # Try to parse JSON from stdout first, then stderr (sometimes PowerShell sends JSON to stderr)
                json_data = None
                json_source = None
                
                if stdout.strip():
                    try:
                        json_data = json.loads(stdout.strip())
                        json_source = "stdout"
                    except json.JSONDecodeError:
                        pass
                
                # If stdout didn't have JSON, try stderr
                if json_data is None and stderr.strip():
                    try:
                        json_data = json.loads(stderr.strip())
                        json_source = "stderr"
                    except json.JSONDecodeError:
                        pass
                
                if json_data:
                    request_id = json_data.get('Identity', {}).get('DisplayName', '')
                    status = json_data.get('Status', 'Queued')
                    logger.info(f"Created export request for {email}: {request_id}, Status: {status} (from {json_source})")
                    return True, f"Export request created: {request_id}"
                
                # If no JSON found, check for success messages in stdout or stderr
                output_text = stdout + stderr
                if "The export request has been queued" in output_text or "Export request has been created" in output_text or "MailboxExportRequest" in output_text:
                    logger.info(f"Export request queued for {email} (non-JSON response but appears successful)")
                    return True, "Export request queued"
                
                logger.error(f"Could not parse export request response for {email}: stdout_length={len(stdout)}, stderr_length={len(stderr)}, stdout: {stdout[:200]}, stderr: {stderr[:500]}")
                return False, f"Could not parse export request response (check logs for details)"
            else:
                logger.error(f"PowerShell command failed for {email}: stderr={stderr[:500]}")
                # Check if mailbox doesn't exist or already exported
                if "A request for this mailbox already exists" in stderr or "already exists" in stderr.lower():
                    logger.warning(f"Export request already exists for {email}")
                    return False, "Export request already exists for this mailbox"
                return False, f"Failed to create export request: {stderr[:500]}"
                
        except Exception as e:
            logger.error(f"Exception exporting mailbox {email}: {str(e)}", exc_info=True)
            return False, str(e)
    
    def check_export_request_status(self, email: str) -> Dict[str, Any]:
        """
        Check the status of mailbox export requests for a given email
        
        Args:
            email: Email address of the mailbox
            
        Returns:
            Dictionary with status information: {'completed': bool, 'status': str, 'percent_complete': int}
        """
        cmd = f"""
        $requests = Get-MailboxExportRequest -Mailbox '{email}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Status -ne 'Completed' -and $_.Status -ne 'Failed' -and $_.Status -ne 'Removed' }};
        if ($requests) {{
            $requests | Select-Object -First 1 | Select-Object Status, PercentComplete | ConvertTo-Json -Depth 2
        }} else {{
            @{{ Status = 'Completed'; PercentComplete = 100 }} | ConvertTo-Json -Depth 2
        }}
        """
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success and stdout.strip():
            try:
                data = json.loads(stdout.strip())
                status = data.get('Status', 'Unknown')
                percent_complete = data.get('PercentComplete', 0)
                
                # Status can be: Queued, InProgress, Completed, Failed, Removed
                completed = status in ['Completed', 'Failed', 'Removed']
                
                return {
                    'completed': completed,
                    'status': status,
                    'percent_complete': percent_complete
                }
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse export status for {email}: {e}")
                return {'completed': False, 'status': 'Unknown', 'percent_complete': 0}
        else:
            # If no requests found, assume completed
            logger.debug(f"No export requests found for {email}, assuming completed")
            return {'completed': True, 'status': 'Completed', 'percent_complete': 100}
    
    def wait_for_exports_complete(self, emails: List[str], max_wait_minutes: int = 60, poll_interval_seconds: int = 30) -> Dict[str, Dict]:
        """
        Wait for all export requests to complete, polling their status
        
        Args:
            emails: List of email addresses to check
            max_wait_minutes: Maximum time to wait in minutes
            poll_interval_seconds: How often to poll status (in seconds)
            
        Returns:
            Dictionary mapping email to status info
        """
        max_wait_seconds = max_wait_minutes * 60
        start_time = time.time()
        results = {}
        
        # Initialize results
        for email in emails:
            results[email] = {'completed': False, 'status': 'Checking', 'percent_complete': 0}
        
        logger.info(f"Waiting for {len(emails)} export requests to complete (max {max_wait_minutes} minutes)...")
        
        while time.time() - start_time < max_wait_seconds:
            all_complete = True
            completed_count = 0
            
            for email in emails:
                if results[email]['completed']:
                    completed_count += 1
                    continue
                
                status_info = self.check_export_request_status(email)
                results[email] = status_info
                
                if not status_info['completed']:
                    all_complete = False
                    logger.debug(f"Export for {email}: {status_info['status']} ({status_info['percent_complete']}%)")
            
            if all_complete:
                elapsed = int(time.time() - start_time)
                logger.info(f"All export requests completed in {elapsed} seconds")
                return results
            
            # Log progress every few polls
            if int(time.time() - start_time) % (poll_interval_seconds * 2) == 0:
                elapsed_minutes = int((time.time() - start_time) / 60)
                logger.info(f"Waiting for exports... {completed_count}/{len(emails)} completed ({elapsed_minutes} minutes elapsed)")
            
            time.sleep(poll_interval_seconds)
        
        # Timeout reached
        elapsed_minutes = int((time.time() - start_time) / 60)
        incomplete = [email for email, info in results.items() if not info['completed']]
        logger.warning(f"Timeout reached after {elapsed_minutes} minutes. {len(incomplete)} export(s) still incomplete: {incomplete[:5]}")
        
        return results
    
    def zip_pst_files(self, archive_path: str, zip_filename: str = None, zip_location: str = None) -> Tuple[bool, str]:
        """
        Create a zip file containing all PST files in the archive path
        
        Args:
            archive_path: Path where PST files are located (local Exchange server path or network share)
            zip_filename: Name for the zip file (optional, will auto-generate if not provided)
            zip_location: Where to create the zip file (optional, defaults to archive_path)
            
        Returns:
            Tuple of (success, zip_file_path/error_message)
        """
        try:
            import datetime
            if not zip_filename:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                zip_filename = f"orphaned_mailboxes_{timestamp}.zip"
            
            # Use zip_location if provided, otherwise use archive_path
            zip_base_path = zip_location if zip_location else archive_path
            zip_path = f"{zip_base_path}\\{zip_filename}"
            
            logger.info(f"Creating zip file: {zip_path} from PST files in {archive_path}")
            
            # PowerShell command to zip all PST files
            # Use Compress-Archive to create zip file
            command = f"$pstFiles=Get-ChildItem -Path '{archive_path}' -Filter '*.pst';if($pstFiles.Count -eq 0){{'No PST files found'}}else{{$pstFiles|Compress-Archive -DestinationPath '{zip_path}' -Force;'Zip created successfully'}}"
            
            logger.debug(f"Executing PowerShell zip command")
            success, stdout, stderr = self._run_powershell_command(command)
            
            logger.info(f"PowerShell zip command result: success={success}, stdout_length={len(stdout) if stdout else 0}, stderr_length={len(stderr) if stderr else 0}")
            
            if stdout:
                logger.debug(f"PowerShell zip stdout: {stdout[:500]}")
            if stderr:
                logger.debug(f"PowerShell zip stderr: {stderr[:500]}")
            
            if success:
                if "Zip created successfully" in stdout or "Compress-Archive" in stdout:
                    logger.info(f"Successfully created zip file: {zip_path}")
                    return True, zip_path
                elif "No PST files found" in stdout:
                    logger.warning(f"No PST files found in {archive_path}")
                    return False, "No PST files found to zip"
                else:
                    logger.warning(f"Zip command succeeded but unclear result: {stdout[:200]}")
                    # Assume success if no error
                    return True, zip_path
            else:
                logger.error(f"Failed to create zip file: {stderr[:500]}")
                return False, f"Failed to create zip: {stderr[:500]}"
                
        except Exception as e:
            logger.error(f"Exception creating zip file: {str(e)}", exc_info=True)
            return False, str(e)
    
    def cleanup_pst_files(self, archive_path: str, keep_zip: bool = True) -> Tuple[bool, str]:
        """
        Remove individual PST files from archive path (keeping zip file if keep_zip is True)
        
        Args:
            archive_path: Path where PST files are located (local Exchange server path or network share)
            keep_zip: If True, keep zip files and only remove PST files
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not archive_path:
                logger.warning("Cannot cleanup PST files: archive_path is empty")
                return False, "Archive path is empty"
            
            logger.info(f"Cleaning up PST files in {archive_path}, keep_zip={keep_zip}")
            
            if keep_zip:
                # Remove all PST files but keep zip files
                command = f"$pstFiles=Get-ChildItem -Path '{archive_path}' -Filter '*.pst';if($pstFiles.Count -eq 0){{'No PST files found'}}else{{$pstFiles|Remove-Item -Force;$pstFiles.Count.ToString()+' PST files removed'}}"
            else:
                # Remove all PST and zip files
                command = f"$allFiles=Get-ChildItem -Path '{archive_path}' -Filter '*.pst','*.zip';if($allFiles.Count -eq 0){{'No files found'}}else{{$allFiles|Remove-Item -Force;$allFiles.Count.ToString()+' files removed'}}"
            
            logger.debug(f"Executing PowerShell cleanup command")
            success, stdout, stderr = self._run_powershell_command(command)
            
            logger.info(f"PowerShell cleanup result: success={success}, stdout_length={len(stdout) if stdout else 0}")
            
            if stdout:
                logger.debug(f"PowerShell cleanup stdout: {stdout[:500]}")
            if stderr:
                logger.debug(f"PowerShell cleanup stderr: {stderr[:500]}")
            
            if success:
                if "removed" in stdout or "PST files" in stdout:
                    logger.info(f"Successfully cleaned up PST files: {stdout}")
                    return True, stdout.strip()
                elif "No PST files found" in stdout or "No files found" in stdout:
                    logger.info("No files to clean up")
                    return True, "No files to clean up"
                else:
                    logger.warning(f"Cleanup succeeded but unclear result: {stdout[:200]}")
                    return True, stdout.strip()
            else:
                logger.error(f"Failed to cleanup PST files: {stderr[:500]}")
                return False, f"Failed to cleanup: {stderr[:500]}"
                
        except Exception as e:
            logger.error(f"Exception cleaning up PST files: {str(e)}", exc_info=True)
            return False, str(e)
    
    def remove_mailbox(self, email: str, permanent: bool = False) -> Tuple[bool, str]:
        """
        Remove a mailbox from Exchange
        
        Args:
            email: Email address of the mailbox to remove
            permanent: If True, permanently delete the mailbox. If False, disconnect it.
            
        Returns:
            Tuple of (success, message/error)
        """
        try:
            if permanent:
                # Permanently delete mailbox (requires Confirm parameter)
                command = f"Disable-Mailbox -Identity '{email}' -Confirm:$false -ErrorAction Stop;Remove-Mailbox -Identity '{email}' -Permanent:$true -Confirm:$false -ErrorAction Stop;'Mailbox permanently deleted'"
            else:
                # Disconnect mailbox (safer, can be recovered)
                command = f"Disable-Mailbox -Identity '{email}' -Confirm:$false -ErrorAction Stop;'Mailbox disconnected'"
            
            success, stdout, stderr = self._run_powershell_command(command)
            
            if success:
                return True, "Mailbox removed successfully"
            else:
                return False, f"Failed to remove mailbox: {stderr}"
                
        except Exception as e:
            logger.error(f"Error removing mailbox {email}: {str(e)}")
            return False, str(e)
    
    def download_zip_file(self, zip_path: str) -> Tuple[bool, bytes, str]:
        """
        Download a zip file from Exchange server to the Flask app
        
        Args:
            zip_path: Full path to the zip file on Exchange server (e.g., C:\\Temp\\ExchangeArchives\\file.zip)
            
        Returns:
            Tuple of (success, file_bytes, error_message)
            If success is False, file_bytes will be None
        """
        try:
            logger.info(f"Downloading zip file from Exchange server: {zip_path}")
            
            # Use PowerShell to read the file and convert to base64
            # We'll read the file in chunks to avoid command line length limits
            command = f"$filePath='{zip_path}';if(Test-Path $filePath){{$bytes=[System.IO.File]::ReadAllBytes($filePath);[System.Convert]::ToBase64String($bytes)}}else{{'File not found'}}"
            
            success, stdout, stderr = self._run_powershell_command(command)
            
            if success and stdout and "File not found" not in stdout:
                try:
                    import base64
                    file_bytes = base64.b64decode(stdout.strip())
                    logger.info(f"Successfully downloaded zip file: {len(file_bytes)} bytes")
                    return True, file_bytes, None
                except Exception as e:
                    logger.error(f"Failed to decode base64 file data: {str(e)}")
                    return False, None, f"Failed to decode file: {str(e)}"
            else:
                error_msg = stderr if stderr else "File not found or download failed"
                logger.error(f"Failed to download zip file: {error_msg}")
                return False, None, error_msg
                
        except Exception as e:
            logger.error(f"Exception downloading zip file: {str(e)}", exc_info=True)
            return False, None, str(e)
    
    def transfer_zip_file(self, zip_path: str, destination_path: str) -> Tuple[bool, str]:
        """
        Transfer a zip file from Exchange server to a file store server
        
        Args:
            zip_path: Full path to the zip file on Exchange server
            destination_path: Destination path on file store server (network share)
            
        Returns:
            Tuple of (success, message/error)
        """
        try:
            logger.info(f"Transferring zip file from {zip_path} to {destination_path}")
            
            # Use PowerShell to copy the file to the network share
            command = f"$src='{zip_path}';$dest='{destination_path}';if(Test-Path $src){{Copy-Item -Path $src -Destination $dest -Force -ErrorAction Stop;'Transferred successfully'}}else{{'Source file not found'}}"
            
            success, stdout, stderr = self._run_powershell_command(command)
            
            if success and "Transferred successfully" in stdout:
                logger.info(f"Successfully transferred zip file to: {destination_path}")
                return True, f"File transferred to {destination_path}"
            else:
                error_msg = stderr if stderr else stdout
                logger.error(f"Failed to transfer zip file: {error_msg}")
                return False, f"Failed to transfer: {error_msg}"
                
        except Exception as e:
            logger.error(f"Exception transferring zip file: {str(e)}", exc_info=True)
            return False, str(e)
    
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test connection to Exchange server
        
        Returns:
            Tuple of (success, message)
        """
        cmd = "Get-ExchangeServer | Select-Object Name, AdminDisplayVersion | ConvertTo-Json"
        
        success, stdout, stderr = self._run_powershell_command(cmd)
        
        if success:
            return True, "Connection successful"
        else:
            return False, f"Connection failed: {stderr}"
