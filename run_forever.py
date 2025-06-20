import subprocess
import time
import requests
import os
import signal

LOCAL_VERSION_FILE = "app/version.py"
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/manayethas/GEEKS-AD-Plus/dev/app/version.py"


def get_local_version():
    with open(LOCAL_VERSION_FILE) as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().replace('"', '').replace("'", "")
    return None

def get_latest_github_version():
    resp = requests.get(GITHUB_VERSION_URL)
    if resp.status_code == 200:
        for line in resp.text.splitlines():
            if line.startswith("__version__"):
                return line.split("=")[1].strip().replace('"', '').replace("'", "")
    return None

def update_and_restart():
    subprocess.run(["git", "pull", "origin", "dev"])
    subprocess.run(["pip3", "install", "-r", "requirements.txt"])


def main():
    while True:
        # Start the Flask app
        flask_proc = subprocess.Popen(["python3", "app.py"])
        print("App started on http://0.0.0.0:5000. Checking for updates every 10 minutes.")
        try:
            while True:
                time.sleep(600)  # 10 minutes
                local_version = get_local_version()
                latest_version = get_latest_github_version()
                if latest_version and latest_version != local_version:
                    print(f"Update found: {local_version} -> {latest_version}. Updating...")
                    flask_proc.terminate()
                    flask_proc.wait()
                    update_and_restart()
                    break  # Restart the loop to relaunch the app
        except KeyboardInterrupt:
            print("Shutting down.")
            flask_proc.terminate()
            flask_proc.wait()
            break

if __name__ == "__main__":
    main() 