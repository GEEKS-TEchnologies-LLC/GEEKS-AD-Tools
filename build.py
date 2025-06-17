#!/usr/bin/env python3
"""
GEEKS-AD-Plus Automated Build Script
Builds and configures the complete GEEKS-AD-Plus system
"""

import os
import sys
import subprocess
import shutil
import json
import platform
from pathlib import Path
from datetime import datetime

class GEEKSBuildSystem:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.build_dir = self.project_root / "build"
        self.dist_dir = self.project_root / "dist"
        self.log_file = self.project_root / "build.log"
        self.config_file = self.project_root / "build_config.json"
        
        # Build configuration
        self.config = {
            "version": "1.3.0",
            "python_version": "3.7+",
            "platform": platform.system(),
            "build_date": datetime.now().isoformat(),
            "components": {
                "web_app": True,
                "credential_provider": True,
                "database": True,
                "logs": True
            }
        }
        
        # Colors for output
        self.colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "purple": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "bold": "\033[1m",
            "end": "\033[0m"
        }
    
    def log(self, message, level="INFO", color="white"):
        """Log a message with timestamp and color"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        
        # Console output with color
        print(f"{self.colors.get(color, '')}{log_message}{self.colors['end']}")
        
        # File logging
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
    
    def run_command(self, command, cwd=None, check=True):
        """Run a shell command with error handling"""
        self.log(f"Running: {command}", "DEBUG", "cyan")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd or self.project_root,
                capture_output=True,
                text=True,
                check=check
            )
            
            if result.stdout:
                self.log(f"Output: {result.stdout.strip()}", "DEBUG", "cyan")
            
            return result
            
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {e}", "ERROR", "red")
            if e.stderr:
                self.log(f"Error output: {e.stderr}", "ERROR", "red")
            if check:
                raise
            return e
    
    def check_prerequisites(self):
        """Check if all prerequisites are met"""
        self.log("Checking prerequisites...", "INFO", "blue")
        
        # Check Python version
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 7):
            self.log(f"Python 3.7+ required, found {python_version.major}.{python_version.minor}", "ERROR", "red")
            return False
        
        self.log(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}", "INFO", "green")
        
        # Check if pip is available
        try:
            result = self.run_command("pip --version", check=False)
            if result.returncode == 0:
                self.log("pip is available", "INFO", "green")
            else:
                self.log("pip not found", "ERROR", "red")
                return False
        except Exception as e:
            self.log(f"Error checking pip: {e}", "ERROR", "red")
            return False
        
        # Check if virtual environment tools are available
        try:
            result = self.run_command("python -m venv --help", check=False)
            if result.returncode == 0:
                self.log("venv module is available", "INFO", "green")
            else:
                self.log("venv module not found", "WARNING", "yellow")
        except Exception as e:
            self.log(f"Error checking venv: {e}", "WARNING", "yellow")
        
        return True
    
    def create_directories(self):
        """Create necessary directories"""
        self.log("Creating build directories...", "INFO", "blue")
        
        directories = [
            self.build_dir,
            self.dist_dir,
            self.project_root / "app" / "logs",
            self.project_root / "app" / "static",
            self.project_root / "app" / "templates",
            self.project_root / "app" / "branding",
            self.project_root / "bug_reports",
            self.project_root / "windows-credential-provider" / "build",
            self.project_root / "windows-credential-provider" / "dist"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            self.log(f"Created directory: {directory}", "DEBUG", "cyan")
    
    def install_dependencies(self):
        """Install Python dependencies"""
        self.log("Installing Python dependencies...", "INFO", "blue")
        
        # Check if virtual environment exists
        venv_path = self.project_root / "venv"
        if not venv_path.exists():
            self.log("Creating virtual environment...", "INFO", "blue")
            self.run_command("python -m venv venv")
        
        # Determine pip command based on platform
        if platform.system() == "Windows":
            pip_cmd = "venv\\Scripts\\pip"
        else:
            pip_cmd = "venv/bin/pip"
        
        # Upgrade pip
        self.log("Upgrading pip...", "INFO", "blue")
        self.run_command(f"{pip_cmd} install --upgrade pip")
        
        # Install requirements
        requirements_file = self.project_root / "requirements.txt"
        if requirements_file.exists():
            self.log("Installing requirements...", "INFO", "blue")
            self.run_command(f"{pip_cmd} install -r requirements.txt")
        else:
            self.log("requirements.txt not found, installing basic dependencies", "WARNING", "yellow")
            basic_deps = [
                "flask",
                "flask-sqlalchemy",
                "ldap3",
                "python-dotenv",
                "requests",
                "cryptography"
            ]
            for dep in basic_deps:
                self.run_command(f"{pip_cmd} install {dep}")
    
    def setup_database(self):
        """Initialize the database"""
        self.log("Setting up database...", "INFO", "blue")
        
        try:
            # Determine python command based on platform
            if platform.system() == "Windows":
                python_cmd = "venv\\Scripts\\python"
            else:
                python_cmd = "venv/bin/python"
            
            # Initialize database
            self.log("Initializing database...", "INFO", "blue")
            self.run_command(f"{python_cmd} -c \"from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()\"")
            
            self.log("Database setup completed", "INFO", "green")
            
        except Exception as e:
            self.log(f"Database setup failed: {e}", "ERROR", "red")
            return False
        
        return True
    
    def build_credential_provider(self):
        """Build the Windows Credential Provider"""
        self.log("Building Windows Credential Provider...", "INFO", "blue")
        
        cp_dir = self.project_root / "windows-credential-provider"
        if not cp_dir.exists():
            self.log("Credential provider directory not found", "WARNING", "yellow")
            return False
        
        # Check if Visual Studio is available (Windows only)
        if platform.system() == "Windows":
            try:
                # Try to find MSBuild
                result = self.run_command("where msbuild", check=False)
                if result.returncode == 0:
                    msbuild_path = result.stdout.strip().split('\n')[0]
                    self.log(f"Found MSBuild: {msbuild_path}", "INFO", "green")
                    
                    # Build the credential provider
                    build_cmd = f"msbuild GEEKS-CredentialProvider.sln /p:Configuration=Release /p:Platform=x64"
                    self.run_command(build_cmd, cwd=cp_dir)
                    
                    # Check if build was successful
                    dll_path = cp_dir / "x64" / "Release" / "GEEKS-CredentialProvider.dll"
                    if dll_path.exists():
                        self.log("Credential provider built successfully", "INFO", "green")
                        
                        # Copy to dist directory
                        dist_dll = self.dist_dir / "GEEKS-CredentialProvider.dll"
                        shutil.copy2(dll_path, dist_dll)
                        self.log(f"Copied DLL to: {dist_dll}", "INFO", "green")
                        
                        return True
                    else:
                        self.log("Credential provider build failed - DLL not found", "ERROR", "red")
                        return False
                else:
                    self.log("MSBuild not found - skipping credential provider build", "WARNING", "yellow")
                    return False
                    
            except Exception as e:
                self.log(f"Error building credential provider: {e}", "ERROR", "red")
                return False
        else:
            self.log("Credential provider build skipped (not on Windows)", "INFO", "yellow")
            return True
    
    def create_configuration(self):
        """Create default configuration files"""
        self.log("Creating configuration files...", "INFO", "blue")
        
        # Create default config.json
        config_data = {
            "ad_server": "localhost",
            "ad_port": 389,
            "ad_base_dn": "DC=example,DC=com",
            "ad_bind_dn": "CN=Administrator,DC=example,DC=com",
            "ad_bind_password": "",
            "admin_groups": ["Domain Admins"],
            "debug": False,
            "secret_key": "",
            "portal_url": "http://localhost:5000"
        }
        
        config_file = self.project_root / "config.json"
        if not config_file.exists():
            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)
            self.log("Created default config.json", "INFO", "green")
        
        # Create .env file
        env_file = self.project_root / ".env"
        if not env_file.exists():
            env_content = """# GEEKS-AD-Plus Environment Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DEBUG=False
"""
            with open(env_file, "w") as f:
                f.write(env_content)
            self.log("Created default .env file", "INFO", "green")
    
    def run_tests(self):
        """Run basic tests"""
        self.log("Running basic tests...", "INFO", "blue")
        
        try:
            # Determine python command based on platform
            if platform.system() == "Windows":
                python_cmd = "venv\\Scripts\\python"
            else:
                python_cmd = "venv/bin/python"
            
            # Test imports
            test_script = """
import sys
sys.path.insert(0, '.')

try:
    from app import create_app
    from app.models import User, AdminUser, AuditLog
    from app.ad import load_ad_config, test_ad_connection
    from app.audit import log_admin_action
    from app.bug_report import generate_bug_report
    print("All imports successful")
except Exception as e:
    print(f"Import error: {e}")
    sys.exit(1)
"""
            
            result = self.run_command(f"{python_cmd} -c \"{test_script}\"")
            if result.returncode == 0:
                self.log("Basic tests passed", "INFO", "green")
                return True
            else:
                self.log("Basic tests failed", "ERROR", "red")
                return False
                
        except Exception as e:
            self.log(f"Error running tests: {e}", "ERROR", "red")
            return False
    
    def create_package(self):
        """Create distribution package"""
        self.log("Creating distribution package...", "INFO", "blue")
        
        # Create package structure
        package_dir = self.dist_dir / f"GEEKS-AD-Plus-{self.config['version']}"
        package_dir.mkdir(exist_ok=True)
        
        # Copy application files
        app_files = [
            "app.py",
            "requirements.txt",
            "README.md",
            "run_forever.py",
            ".gitignore"
        ]
        
        for file_name in app_files:
            src = self.project_root / file_name
            if src.exists():
                shutil.copy2(src, package_dir)
        
        # Copy app directory
        app_src = self.project_root / "app"
        app_dst = package_dir / "app"
        if app_src.exists():
            shutil.copytree(app_src, app_dst, dirs_exist_ok=True)
        
        # Copy credential provider
        cp_src = self.project_root / "windows-credential-provider"
        cp_dst = package_dir / "windows-credential-provider"
        if cp_src.exists():
            shutil.copytree(cp_src, cp_dst, dirs_exist_ok=True)
        
        # Create build info
        build_info = {
            "build_date": self.config["build_date"],
            "version": self.config["version"],
            "platform": self.config["platform"],
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }
        
        with open(package_dir / "build_info.json", "w") as f:
            json.dump(build_info, f, indent=2)
        
        # Create installation script
        install_script = self.create_install_script()
        with open(package_dir / "install.py", "w") as f:
            f.write(install_script)
        
        self.log(f"Package created: {package_dir}", "INFO", "green")
        return package_dir
    
    def create_install_script(self):
        """Create installation script for the package"""
        return '''#!/usr/bin/env python3
"""
GEEKS-AD-Plus Installation Script
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def install():
    print("Installing GEEKS-AD-Plus...")
    
    # Install dependencies
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    # Setup database
    from app import create_app, db
    app = create_app()
    with app.app_context():
        db.create_all()
    
    print("Installation completed!")

if __name__ == "__main__":
    install()
'''
    
    def save_build_config(self):
        """Save build configuration"""
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)
        self.log(f"Build configuration saved: {self.config_file}", "INFO", "green")
    
    def build(self):
        """Main build process"""
        self.log("Starting GEEKS-AD-Plus build process...", "INFO", "bold")
        self.log(f"Build version: {self.config['version']}", "INFO", "blue")
        self.log(f"Platform: {self.config['platform']}", "INFO", "blue")
        
        # Clear previous build log
        if self.log_file.exists():
            self.log_file.unlink()
        
        try:
            # Check prerequisites
            if not self.check_prerequisites():
                self.log("Prerequisites check failed", "ERROR", "red")
                return False
            
            # Create directories
            self.create_directories()
            
            # Install dependencies
            self.install_dependencies()
            
            # Setup database
            if not self.setup_database():
                self.log("Database setup failed", "ERROR", "red")
                return False
            
            # Build credential provider
            self.build_credential_provider()
            
            # Create configuration
            self.create_configuration()
            
            # Run tests
            if not self.run_tests():
                self.log("Tests failed", "WARNING", "yellow")
            
            # Create package
            package_dir = self.create_package()
            
            # Save build configuration
            self.save_build_config()
            
            self.log("Build completed successfully!", "INFO", "bold")
            self.log(f"Package location: {package_dir}", "INFO", "green")
            self.log(f"Build log: {self.log_file}", "INFO", "green")
            
            return True
            
        except Exception as e:
            self.log(f"Build failed: {e}", "ERROR", "red")
            return False

def main():
    """Main entry point"""
    builder = GEEKSBuildSystem()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "clean":
            # Clean build artifacts
            import shutil
            if builder.build_dir.exists():
                shutil.rmtree(builder.build_dir)
            if builder.dist_dir.exists():
                shutil.rmtree(builder.dist_dir)
            if builder.log_file.exists():
                builder.log_file.unlink()
            print("Build artifacts cleaned")
            
        elif command == "test":
            # Run tests only
            builder.check_prerequisites()
            builder.install_dependencies()
            builder.run_tests()
            
        elif command == "package":
            # Create package only
            builder.create_directories()
            builder.create_package()
            
        else:
            print(f"Unknown command: {command}")
            print("Available commands: clean, test, package")
    else:
        # Full build
        success = builder.build()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 