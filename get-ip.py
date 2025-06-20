#!/usr/bin/env python3
"""
GEEKS-AD-Plus IP Address Helper
Shows the IP addresses where the application can be accessed
"""

import socket
import subprocess
import platform

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_all_ips():
    """Get all available IP addresses"""
    ips = []
    try:
        hostname = socket.gethostname()
        ips.append(("Hostname", hostname))
        
        # Get local IP
        local_ip = get_local_ip()
        ips.append(("Local IP", local_ip))
        
        # Get all interface IPs
        if platform.system() == "Windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "IPv4" in line and "192.168" in line:
                        ip = line.split(':')[-1].strip()
                        ips.append(("Network IP", ip))
        else:
            result = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
            if result.returncode == 0:
                for ip in result.stdout.strip().split():
                    if ip != local_ip and ip.startswith(('192.168', '10.', '172.')):
                        ips.append(("Network IP", ip))
                        
    except Exception as e:
        print(f"Error getting IP addresses: {e}")
    
    return ips

def main():
    print("=" * 50)
    print("GEEKS-AD-Plus Network Access Information")
    print("=" * 50)
    
    ips = get_all_ips()
    
    print("\nYour application will be accessible at:")
    print("- Local access: http://localhost:5000")
    
    for label, ip in ips:
        if ip and ip != "127.0.0.1":
            print(f"- {label}: http://{ip}:5000")
    
    print("\nAdmin interfaces:")
    for label, ip in ips:
        if ip and ip != "127.0.0.1":
            print(f"- {label} Admin: http://{ip}:5000/admin/login")
            print(f"- {label} Setup: http://{ip}:5000/setup")
    
    print("\n" + "=" * 50)
    print("Note: Make sure your firewall allows connections on port 5000")
    print("=" * 50)

if __name__ == "__main__":
    main() 