import requests
import time
import json
import os
import datetime

LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "https://license.geeks-tech.win/api/validate")
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
CACHE_FILE = os.path.join(os.path.dirname(__file__), 'license_cache.json')
PRODUCT_ID = 'GEEKS-AD-PLUS'
TRIAL_DAYS = 14

# --- License Cache Helpers ---
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(data):
    with open(CACHE_FILE, "w") as f:
        json.dump(data, f)

# --- License Info from config.json ---
def get_license_info():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        return config.get('base_license_key', ''), config.get('product_id', PRODUCT_ID)
    return '', PRODUCT_ID

# --- License Validation ---
def validate_license(key, product_id=PRODUCT_ID):
    # Always use the correct product ID
    product_id = PRODUCT_ID
    try:
        print(f"[DEBUG] validate_license: URL={LICENSE_SERVER_URL}")
        print(f"[DEBUG] validate_license: Payload={{'key': '{key}', 'product_id': '{product_id}'}}")
        response = requests.post(
            LICENSE_SERVER_URL,
            json={"key": key, "product_id": product_id},
            timeout=10
        )
        print(f"[DEBUG] validate_license: Response status={response.status_code}")
        print(f"[DEBUG] validate_license: Response body={response.text}")
        if response.status_code == 200:
            data = response.json()
            if data.get("valid"):
                cache = {
                    "last_check": time.time(),
                    "valid": True,
                    "license_tier": data["license"].get("license_tier"),
                    "expires_at": data["license"].get("expires_at"),
                }
                save_cache(cache)
                return cache
            else:
                cache = {
                    "last_check": time.time(),
                    "valid": False,
                    "reason": data.get("reason")
                }
                save_cache(cache)
                return cache
        else:
            return None
    except Exception as e:
        print("Error contacting license server:", e)
        return None

# --- Trial License Request ---
def request_trial_license():
    # Load company info from config.json
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
    else:
        config = {}
    company_name = config.get('company_name', '')
    email = config.get('email', '')
    contact_name = config.get('contact_name', '')
    phone = config.get('phone', '')
    # Force product_id to GEEKS-AD-PLUS
    product_id = PRODUCT_ID
    trial_url = LICENSE_SERVER_URL.replace('/api/validate', '/api/activate-trial')
    payload = {
        "contact_name": contact_name,
        "email": email,
        "number": phone,
        "company": company_name,
        "product_id": product_id
    }
    print(f"[DEBUG] request_trial_license: URL={trial_url}")
    print(f"[DEBUG] request_trial_license: Payload={payload}")
    try:
        response = requests.post(
            trial_url,
            json=payload,
            timeout=10
        )
        print(f"[DEBUG] request_trial_license: Response status={response.status_code}")
        print(f"[DEBUG] request_trial_license: Response body={response.text}")
        if response.status_code == 201:
            data = response.json()
            trial_key = data.get('license_key')
            trial_start = datetime.date.today().isoformat()
            if trial_key:
                config['trial_license_key'] = trial_key
                config['trial_start_date'] = trial_start
                with open(CONFIG_PATH, 'w') as f:
                    json.dump(config, f, indent=2)
                return trial_key, trial_start
            else:
                raise Exception('No license_key in response')
        else:
            print("Failed to get trial license:", response.text)
            raise Exception(f'License server error: {response.status_code}')
    except Exception as e:
        print(f"Error requesting trial license: {e}")
        # Fallback to dummy key for local testing
        trial_key = 'TRIAL-KEY-XXXXX-XXXXX-XXXXX'
        trial_start = datetime.date.today().isoformat()
        config['trial_license_key'] = trial_key
        config['trial_start_date'] = trial_start
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        return trial_key, trial_start

# --- Trial License Validation ---
def is_trial_valid():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        trial_key = config.get('trial_license_key', '')
        trial_start = config.get('trial_start_date', '')
        if trial_key and trial_start:
            start_date = datetime.date.fromisoformat(trial_start)
            days_used = (datetime.date.today() - start_date).days
            if days_used < TRIAL_DAYS:
                return True
    return False

# --- Main License Check ---
def is_license_or_trial_valid():
    # Check full license
    license_key, product_id = get_license_info()
    if license_key:
        cache = validate_license(license_key, product_id)
        if cache and cache.get('valid'):
            expires_at = cache.get('expires_at')
            if expires_at:
                if datetime.date.fromisoformat(expires_at) >= datetime.date.today():
                    return True
                else:
                    return False
            return True
        else:
            return False
    # If not, check trial
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        trial_key = config.get('trial_license_key', '')
        trial_start = config.get('trial_start_date', '')
        if trial_key and trial_start:
            # Always validate the trial key with the server
            cache = validate_license(trial_key, PRODUCT_ID)
            if cache and cache.get('valid'):
                start_date = datetime.date.fromisoformat(trial_start)
                days_used = (datetime.date.today() - start_date).days
                if days_used < TRIAL_DAYS:
                    return True
    return False

def is_plus_activated():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        plus_key = config.get('plus_license_key', '')
        if plus_key:
            cache = validate_license(plus_key, 'GEEKS-AD-PLUS')
            return cache and cache.get('valid', False)
    return False

def is_reporting_activated():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        reporting_key = config.get('reporting_license_key', '')
        if reporting_key:
            cache = validate_license(reporting_key, 'GEEKS-RESET-TOOLS')
            return cache and cache.get('valid', False)
    return False