#!/usr/bin/env python3
"""
GCP-Hound BloodHound Node Registration with comprehensive reset
"""

import argparse
import json
import logging
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BloodHoundRegistrar:
    def __init__(self, url, username, password):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.token = None

        logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def login(self):
        login_url = self.url + '/api/v2/login'
        payload = {
            "login_method": "secret",
            "username": self.username,
            "secret": self.password
        }
        try:
            response = self.session.post(login_url, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self.token = data['data']['session_token']
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                self.logger.info("✅ Login successful to BloodHound")
                return True
            else:
                self.logger.error(f"❌ Login failed: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Login error: {e}")
            return False

    def logout(self):
        logout_url = self.url + '/api/v2/logout'
        try:
            self.session.post(logout_url)
            self.logger.info("🔐 Logged out from BloodHound")
        except Exception as e:
            self.logger.warning(f"⚠️ Logout warning: {e}")

    def get_existing_kinds(self):
        try:
            response = self.session.get(self.url + '/api/v2/custom-nodes')
            if response.status_code == 200:
                data = response.json()
                kinds = [item.get('kindName') for item in data.get('data', []) if item.get('kindName')]
                self.logger.info(f"Found {len(kinds)} custom node kinds: {kinds}")
                return kinds
            else:
                self.logger.warning(f"Failed to get kinds: {response.status_code}")
                return []
        except Exception as e:
            self.logger.warning(f"⚠️ Error fetching existing kinds: {e}")
            return []

    def delete_kind(self, kind):
        try:
            response = self.session.delete(self.url + f'/api/v2/custom-nodes/{kind}')
            if response.status_code == 200:
                self.logger.info(f"🗑️ Deleted existing kind: {kind}")
                return True
            return False
        except Exception as e:
            self.logger.warning(f"⚠️ Error deleting kind {kind}: {e}")
            return False

    def reset_all_kinds(self):
        """Reset/delete ALL existing custom node kinds (not just GCP ones)"""
        self.logger.info("🔄 Resetting ALL existing custom node kinds...")
        existing_kinds = self.get_existing_kinds()
        
        if not existing_kinds:
            self.logger.info("ℹ️ No existing custom node kinds found to reset")
            return True
            
        self.logger.info(f"Found {len(existing_kinds)} kinds to reset: {existing_kinds}")
        for kind in existing_kinds:
            self.delete_kind(kind)
        return True

    def register_nodes(self, model):
        if 'custom_kinds' not in model or not model['custom_kinds']:
            self.logger.error("❌ No custom kinds found in model")
            return False
        payload = {"custom_types": {}}
        for kind_name, kind_config in model['custom_kinds'].items():
            payload["custom_types"][kind_name] = {
                "icon": kind_config.get('icon', {}),
                "searchable_properties": kind_config.get('searchable_properties', []),
                "display_property": kind_config.get('display_property', 'name')
            }
        self.logger.info(f"📝 Registering {len(model['custom_kinds'])} custom node types...")
        try:
            response = self.session.post(self.url + '/api/v2/custom-nodes', json=payload, timeout=60)
            if response.status_code in [200, 201]:
                self.logger.info(f"✅ Successfully registered {len(model['custom_kinds'])} kinds")
                for kind_name in model['custom_kinds'].keys():
                    self.logger.info(f"   📌 {kind_name}")
                return True
            elif response.status_code == 409:
                self.logger.info("ℹ️ Custom node kinds already registered")
                return True
            else:
                self.logger.error(f"❌ Registration failed: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Registration error: {e}")
            return False

    def load_model(self, file_path):
        try:
            with open(file_path, 'r') as f:
                model = json.load(f)
            self.logger.info(f"📋 Loaded model from: {file_path}")
            self.logger.info(f"   Custom kinds: {len(model.get('custom_kinds', {}))}")
            return model
        except Exception as e:
            self.logger.error(f"❌ Error loading model from {file_path}: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(description="Register GCP custom nodes in BloodHound")
    parser.add_argument('-s', '--server', required=True, help='BloodHound server URL')
    parser.add_argument('-u', '--username', required=True, help='BloodHound username')
    parser.add_argument('-p', '--password', required=True, help='BloodHound password')
    parser.add_argument('-m', '--model', default='gcp-model.json', help='Path to GCP model JSON file')
    parser.add_argument('--reset', action='store_true', help='Reset ALL existing custom node kinds before registering')
    parser.add_argument('--list-existing', action='store_true', help='List existing custom node kinds and exit')

    args = parser.parse_args()

    print("🔐 GCP-Hound BloodHound Node Registration")
    print("=" * 60)

    registrar = BloodHoundRegistrar(args.server, args.username, args.password)
    if not registrar.login():
        print("❌ Failed to authenticate with BloodHound")
        sys.exit(1)

    try:
        if args.list_existing:
            existing = registrar.get_existing_kinds()
            print(f"\n📋 Existing custom node kinds ({len(existing)}):")
            for kind in existing:
                print(f"   • {kind}")
            return

        if args.reset:
            if not registrar.reset_all_kinds():  # CHANGED: reset ALL nodes
                print("⚠️ Reset completed with some warnings")

        model = registrar.load_model(args.model)
        if model is None:
            print("❌ Could not load model file")
            sys.exit(1)

        if registrar.register_nodes(model):
            print("\n🎉 SUCCESS! GCP custom nodes registered")
            print("=" * 60)
            print("✅ Custom GCP node types configured")
            print("✅ Icons and search properties ready")
            print("\n💡 Next Steps:")
            print("   1. Run: python3 gcp-hound.py")
            print("   2. Upload JSON to BloodHound")
            print("   3. Use Cypher: MATCH (sa:GCPServiceAccount) RETURN sa")
        else:
            print("❌ Registration failed")
            sys.exit(1)

    finally:
        registrar.logout()


if __name__ == '__main__':
    main()
