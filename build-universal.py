#!/usr/bin/env python3
"""
GEEKS-AD-Plus Universal Build Script
Works across both dev and stable branches
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def detect_python_command():
    """Detect the correct Python command for the system"""
    if platform.system() == "Windows":
        return "python"
    else:
        # Try python3 first, then python
        try:
            result = subprocess.run(["python3", "--version"], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return "python3"
        except:
            pass
        
        try:
            result = subprocess.run(["python", "--version"], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return "python"
        except:
            pass
        
        return "python3"  # Default fallback

def detect_branch():
    """Detect the current git branch"""
    try:
        result = subprocess.run(["git", "branch", "--show-current"],
                              capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            # Fallback method
            result = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
    except Exception:
        pass
    
    return "unknown"

def main():
    """Main entry point"""
    python_cmd = detect_python_command()
    current_branch = detect_branch()
    
    print("=" * 50)
    print("GEEKS-AD-Plus Universal Build Script")
    print("=" * 50)
    print(f"Python command: {python_cmd}")
    print(f"Current branch: {current_branch}")
    print(f"Platform: {platform.system()}")
    print("=" * 50)
    
    # Check if build.py exists
    build_script = Path("build.py")
    if not build_script.exists():
        print("ERROR: build.py not found in current directory")
        print("Please run this script from the GEEKS-AD-Plus project root")
        sys.exit(1)
    
    # Run the build script
    print("Starting build process...")
    print()
    
    try:
        # Pass all arguments to the build script
        cmd = [python_cmd, "build.py"] + sys.argv[1:]
        result = subprocess.run(cmd, check=False)
        
        if result.returncode == 0:
            print()
            print("=" * 50)
            print("Build completed successfully!")
            print("=" * 50)
        else:
            print()
            print("=" * 50)
            print("Build failed!")
            print("=" * 50)
            sys.exit(result.returncode)
            
    except KeyboardInterrupt:
        print("\nBuild interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Build error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 