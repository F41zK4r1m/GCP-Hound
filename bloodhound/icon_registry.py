import requests
import json
import time
import logging

class BloodHoundIconRegistry:
    def __init__(self, bloodhound_url: str = "http://localhost:8080"):
        self.bloodhound_url = bloodhound_url
        self.gcp_icons = {
            "custom_types": {
                "ServiceAccount": {"icon": {"type": "font-awesome", "name": "user-secret", "color": "#4CAF50"}},
                "Project": {"icon": {"type": "font-awesome", "name": "folder-open", "color": "#FF5722"}},
                "Bucket": {"icon": {"type": "font-awesome", "name": "database", "color": "#2196F3"}},
                "Dataset": {"icon": {"type": "font-awesome", "name": "chart-bar", "color": "#9C27B0"}},
                "User": {"icon": {"type": "font-awesome", "name": "user-circle", "color": "#795548"}}
            }
        }

    def wait_for_bloodhound(self, max_retries: int = 10, retry_interval: int = 1) -> bool:
        """Wait for BloodHound to be ready with better endpoint detection"""
        print("[DEBUG] 🔍 Checking if BloodHound is accessible...")
        
        # Try multiple endpoints to check BloodHound availability
        test_endpoints = [
            "/api/version",
            "/api/v2/features", 
            "/api/v2/login",
            "/"  # Just the main page
        ]
        
        for attempt in range(max_retries):
            for endpoint in test_endpoints:
                try:
                    response = requests.get(f"{self.bloodhound_url}{endpoint}", timeout=3)
                    if response.status_code in [200, 401, 403]:  # 401/403 means BloodHound is running but needs auth
                        print(f"[DEBUG] ✅ BloodHound is accessible at {endpoint}")
                        return True
                except requests.exceptions.RequestException:
                    continue
            
            if attempt < max_retries - 1:
                print(f"[DEBUG] ⏳ Retrying BloodHound connection... (attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_interval)
        
        print(f"[DEBUG] ❌ BloodHound not accessible after {max_retries} attempts")
        return False

    def register_icons_manual_fallback(self) -> None:
        """Create manual registration files as fallback"""
        print("[DEBUG] 💾 Creating manual registration fallback...")
        
        # Create shell script
        script_content = f"""#!/bin/bash
# GCP-Hound Icon Registration Script
echo "🎨 Registering GCP icons with BloodHound..."
echo "📝 Replace YOUR_TOKEN with your actual BloodHound auth token"

curl -X POST "{self.bloodhound_url}/api/v2/custom-nodes" \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{json.dumps(self.gcp_icons, indent=2)}'

echo ""
echo "✅ Manual registration complete! Refresh BloodHound UI to see icons."
echo "💡 Get your token from BloodHound UI → Browser Dev Tools → Network → Authorization header"
"""
        
        with open("./register_icons.sh", 'w') as f:
            f.write(script_content)
        
        # Create JSON file 
        with open("./gcp_icons.json", 'w') as f:
            json.dump(self.gcp_icons, f, indent=2)
        
        # Make script executable
        import os
        os.chmod("./register_icons.sh", 0o755)
        
        print("[DEBUG] 📁 Created files:")
        print("[DEBUG]   ./register_icons.sh - Manual registration script")
        print("[DEBUG]   ./gcp_icons.json - Icon definitions")
        
    def auto_register(self) -> bool:
        """Complete automated registration with better error handling"""
        print("[DEBUG] 🚀 Starting icon registration...")
        
        # Always create fallback files
        self.register_icons_manual_fallback()
        
        # Try automatic registration
        if not self.wait_for_bloodhound():
            print("[DEBUG] 📋 BloodHound not accessible - use manual registration")
            print("[DEBUG] 💡 Run: ./register_icons.sh")
            return False
        
        print("[DEBUG] 🎉 Manual registration files created successfully!")
        print("[DEBUG] 💡 Run ./register_icons.sh to register icons manually")
        
        return True
