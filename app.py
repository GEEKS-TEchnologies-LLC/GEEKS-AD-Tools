from app import create_app
import os
import json

app = create_app()

def get_port_from_config():
    """Get port from config.json, default to 5000"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                portal_url = config.get('portal_url', 'http://localhost:5000')
                # Extract port from portal_url
                if ':' in portal_url:
                    port_str = portal_url.split(':')[-1].split('/')[0]
                    return int(port_str)
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
    return 5000  # Default port

if __name__ == '__main__':
    port = get_port_from_config()
    app.run(host='0.0.0.0', port=port, debug=True) 