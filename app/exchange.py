import subprocess
import json
import logging
from typing import Dict, List, Optional, Tuple
import re
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
            self.domain = domain or 'sunray'
        
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
            full_command = f"$p='{self.password}';$u='{username_with_domain}';$h='{self.exchange_server}';$c=[System.Management.Automation.PSCredential]::new($u,(ConvertTo-SecureString -AsPlainText -String $p -Force));[System.Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};$so=New-PSSessionOption -SkipCACheck -SkipCNCheck;try{{$s=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri \"https://$h/PowerShell/\" -Credential $c -Authentication Basic -SessionOption $so -AllowRedirection -ErrorAction Stop}}catch{{try{{$s=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri \"https://$h/PowerShell/\" -Credential $c -Authentication Kerberos -SessionOption $so -AllowRedirection -ErrorAction Stop}}catch{{throw \"Failed: $_\"}}}};Import-PSSession $s -DisableNameChecking -AllowClobber|Out-Null;{command};try{{Remove-PSSession $s -EA SilentlyContinue}}catch{{}}"
            
            # Execute the combined command
            result = session.run_ps(full_command)
            
            if result.status_code == 0:
                return True, result.std_out.decode('utf-8'), result.std_err.decode('utf-8')
            else:
                logger.error(f"PowerShell command failed with status {result.status_code}: {result.std_err}")
                return False, result.std_out.decode('utf-8'), result.std_err.decode('utf-8')
                
        except Exception as e:
            logger.error(f"Error running PowerShell command: {str(e)}")
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
                logger.error(f"Failed to parse JSON output: {e}")
                logger.error(f"Stdout (first 1000 chars): {stdout[:1000]}")
                logger.error(f"Stderr (first 1000 chars): {stderr[:1000] if stderr else 'empty'}")
                return {}
        else:
            logger.error(f"PowerShell command failed. Status: {success}")
            logger.error(f"Stdout (first 1000 chars): {stdout[:1000] if stdout else 'empty'}")
            logger.error(f"Stderr (first 1000 chars): {stderr[:1000] if stderr else 'empty'}")
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
                else:
                    return [data]
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse mailbox data: {e}")
                return []
        else:
            logger.error(f"Failed to get mailboxes: {stderr}")
            return []
    
    def find_orphaned_mailboxes(self, active_emails: List[str]) -> Dict[str, List[Dict]]:
        """
        Find mailboxes that exist in Exchange but don't have corresponding active users
        
        Args:
            active_emails: List of email addresses that should have mailboxes
            
        Returns:
            Dictionary with 'orphaned' and 'missing' mailboxes
        """
        all_mailboxes = self.get_all_mailboxes()
        # Convert all active emails to lowercase for case-insensitive comparison
        active_email_set = set(email.lower() for email in active_emails if email)
        
        orphaned = []
        missing = []
        
        # Find mailboxes that exist but shouldn't (orphaned mailboxes)
        for mailbox in all_mailboxes:
            email = (mailbox.get('PrimarySmtpAddress') or '').lower()
            if email and email not in active_email_set:
                orphaned.append(mailbox)
        
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
    
    def archive_mailbox(self, email: str, archive_path: str) -> Tuple[bool, str]:
        """
        Export a mailbox to PST file
        
        Args:
            email: Email address of the mailbox to export
            archive_path: Network path where PST file will be created (must be accessible from Exchange server)
            
        Returns:
            Tuple of (success, message/error)
        """
        try:
            logger.info(f"Starting archive for mailbox: {email} to path: {archive_path}")
            
            # Use New-MailboxExportRequest to export mailbox to PST
            # Note: This requires a network share path accessible from Exchange server
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
    
    def zip_pst_files(self, archive_path: str, zip_filename: str = None) -> Tuple[bool, str]:
        """
        Create a zip file containing all PST files in the archive path
        
        Args:
            archive_path: Network path where PST files are located
            zip_filename: Name for the zip file (optional, will auto-generate if not provided)
            
        Returns:
            Tuple of (success, zip_file_path/error_message)
        """
        try:
            import datetime
            if not zip_filename:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                zip_filename = f"orphaned_mailboxes_{timestamp}.zip"
            
            zip_path = f"{archive_path}\\{zip_filename}"
            
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
            archive_path: Network path where PST files are located
            keep_zip: If True, keep zip files and only remove PST files
            
        Returns:
            Tuple of (success, message)
        """
        try:
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
