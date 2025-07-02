import requests
import os
import json

LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "https://license.geeks-tech.win/api/validate")

# Optionally, load license key and product_id from config.json
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')

def validate_license(key: str, product_id: str) -> bool:
    try:
        payload = {"key": key, "product_id": product_id}
        print(f"[DEBUG] Sending license validation request to {LICENSE_SERVER_URL}")
        print(f"[DEBUG] Payload: {payload}")
        response = requests.post(
            LICENSE_SERVER_URL,
            json=payload,
            timeout=5
        )
        print(f"[DEBUG] Response status: {response.status_code}")
        print(f"[DEBUG] Response content: {response.text}")
        if response.status_code == 200:
            return response.json().get("valid", False)
        return False
    except Exception as e:
        print("License check failed:", e)
        return False

def get_license_keys():
    """
    Returns a dict with keys for each product type, e.g.:
    {
        'base': 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
        'plus': 'YYYYY-YYYYY-YYYYY-YYYYY-YYYYY',
        'reporting': 'ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ'
    }
    """
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        return {
            'base': config.get('base_license_key', ''),
            'plus': config.get('plus_license_key', ''),
            'reporting': config.get('reporting_license_key', '')
        }
    except Exception:
        return {'base': '', 'plus': '', 'reporting': ''}

def is_base_activated():
    keys = get_license_keys()
    return validate_license(keys['base'], 'GEEKS-AD-PLUS')

def is_plus_activated():
    keys = get_license_keys()
    return validate_license(keys['email'], 'GEEKS-EXCHANGE-INJECTOR')

def is_reporting_activated():
    keys = get_license_keys()
    return validate_license(keys['passwords'], 'GEEKS-RESET-TOOLS')

def get_license_info():
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        return config.get('license_key', ''), config.get('product_id', 'GEEKS-AD-TOOLS')
    except Exception:
        return '', 'GEEKS-AD-TOOLS' 