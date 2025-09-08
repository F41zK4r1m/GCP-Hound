#!/usr/bin/env python3
import requests
import getpass
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def register_gcp_icons(url, token):
    """Register GCP icons using the official BloodHound API"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    gcp_types = {
        "ServiceAccount": {"icon": {"type": "font-awesome", "name": "user-tie", "color": "#4285F4"}},
        "Project": {"icon": {"type": "font-awesome", "name": "folder-open", "color": "#34A853"}},
        "Bucket": {"icon": {"type": "font-awesome", "name": "database", "color": "#FBBC04"}},
        "Dataset": {"icon": {"type": "font-awesome", "name": "chart-bar", "color": "#EA4335"}},
        "Secret": {"icon": {"type": "font-awesome", "name": "key", "color": "#FF6D00"}},
        "Instance": {"icon": {"type": "font-awesome", "name": "server", "color": "#9C27B0"}},
        "Cluster": {"icon": {"type": "font-awesome", "name": "cubes", "color": "#00BCD4"}}
    }
    
    payload = {"custom_types": gcp_types}
    
    try:
        response = requests.post(f"{url}/api/v2/custom-nodes", 
                               headers=headers, json=payload, verify=False)
        
        print(f"🔹 API Response: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f"✅ Successfully registered {len(gcp_types)} GCP icon types")
            return True
        elif response.status_code == 409:
            print(f"✅ GCP icons already registered - no changes needed")
            print(f"✅ Icons persist permanently in BloodHound database") 
            return True
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"❌ Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return False

def test_connection(url, token):
    """Test BloodHound API connection"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{url}/api/version", headers=headers, verify=False)
        return response.status_code == 200
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description="Register GCP icons in BloodHound")
    parser.add_argument('--url', required=True, help='BloodHound server URL')
    parser.add_argument('--token', help='BloodHound API token')
    args = parser.parse_args()
    
    print("🔐 BloodHound GCP Icon Registration")
    print("=" * 50)
    
    token = args.token or getpass.getpass("BloodHound API token: ")
    
    if test_connection(args.url, token):
        print(f"✅ Connected to BloodHound")
    else:
        print(f"❌ Connection failed")
        return
    
    success = register_gcp_icons(args.url, token)
    
    if success:
        print("\n🎉 SUCCESS! GCP Integration Ready")
        print("=" * 50)
        print("✅ Custom GCP icons configured")
        print("✅ Search functionality enabled")
        print("\n💡 Next Steps:")
        print("   1. Run: python3 gcp-hound.py")
        print("   2. Upload JSON to BloodHound")
        print("   3. Search for GCP objects!")
    else:
        print("\n❌ Setup failed")

if __name__ == '__main__':
    main()
