#!/usr/bin/env python3
"""
GCP BloodHound Search Extension - Enables GCP objects to be searchable in BloodHound UI
Registers custom node types and enables search functionality for GCP resources
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class GCPBloodHoundSearchExtension:
    def __init__(self, bloodhound_url: str, token: str):
        """Initialize the GCP BloodHound Search Extension
        
        Args:
            bloodhound_url: BloodHound instance URL (e.g., http://localhost:8080)
            token: BloodHound API authentication token
        """
        self.bloodhound_url = bloodhound_url.rstrip('/')
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # GCP node type definitions with icons and colors
        self.gcp_node_types = {
            "ServiceAccount": {
                "icon": "user-tie",
                "color": "#4285F4",
                "searchable_properties": ["name", "displayname", "objectid", "email"],
                "display_property": "displayname"
            },
            "Project": {
                "icon": "folder-open",
                "color": "#34A853", 
                "searchable_properties": ["name", "displayname", "objectid", "projectId"],
                "display_property": "displayname"
            },
            "Bucket": {
                "icon": "database",
                "color": "#FBBC04",
                "searchable_properties": ["name", "displayname", "objectid"],
                "display_property": "displayname"
            },
            "Dataset": {
                "icon": "chart-bar",
                "color": "#EA4335",
                "searchable_properties": ["name", "displayname", "objectid"],
                "display_property": "displayname"
            },
            "Secret": {
                "icon": "key",
                "color": "#FF6D00",
                "searchable_properties": ["name", "displayname", "objectid"],
                "display_property": "displayname"
            },
            "Instance": {
                "icon": "server",
                "color": "#9C27B0",
                "searchable_properties": ["name", "displayname", "objectid"],
                "display_property": "displayname"
            },
            "Cluster": {
                "icon": "cubes",
                "color": "#00BCD4",
                "searchable_properties": ["name", "displayname", "objectid"],
                "display_property": "displayname"
            }
        }
    
    def test_connection(self) -> bool:
        """Test connection to BloodHound API"""
        try:
            response = requests.get(
                f"{self.bloodhound_url}/api/version",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to connect to BloodHound API: {e}")
            return False
    
    def register_gcp_node_types(self) -> Tuple[bool, str]:
        """Register all GCP custom node types with BloodHound
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Simple approach - try to register each node type individually
            registered_types = []
            
            for node_type, config in self.gcp_node_types.items():
                try:
                    # Prepare payload for single node type registration
                    payload = {
                        "kind": node_type,
                        "icon": {
                            "type": "font-awesome",
                            "name": config["icon"],
                            "color": config["color"]
                        },
                        "searchable_properties": config["searchable_properties"],
                        "display_property": config["display_property"]
                    }
                    
                    # Try multiple API endpoints (BloodHound versions may differ)
                    endpoints_to_try = [
                        "/api/v2/custom-nodes",
                        "/api/v1/custom-nodes", 
                        "/api/custom-nodes"
                    ]
                    
                    success = False
                    for endpoint in endpoints_to_try:
                        try:
                            response = requests.post(
                                f"{self.bloodhound_url}{endpoint}",
                                headers=self.headers,
                                json=payload,
                                timeout=30
                            )
                            
                            if response.status_code in [200, 201, 409]:  # 409 = already exists
                                registered_types.append(node_type)
                                success = True
                                break
                                
                        except Exception:
                            continue
                    
                    if not success:
                        logger.warning(f"Failed to register {node_type}")
                        
                except Exception as e:
                    logger.error(f"Error registering {node_type}: {e}")
                    continue
            
            if registered_types:
                return True, f"Successfully registered {len(registered_types)} GCP node types: {', '.join(registered_types)}"
            else:
                # Fallback - try bulk registration
                return self._try_bulk_registration()
                
        except Exception as e:
            error_msg = f"Exception during node type registration: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _try_bulk_registration(self) -> Tuple[bool, str]:
        """Fallback method for bulk registration"""
        try:
            # Try different bulk payload formats
            bulk_payloads = [
                {
                    "custom_types": {
                        node_type: {
                            "icon": {
                                "name": config["icon"],
                                "type": "font-awesome",
                                "color": config["color"]
                            },
                            "searchable_properties": config["searchable_properties"],
                            "display_property": config["display_property"]
                        }
                        for node_type, config in self.gcp_node_types.items()
                    }
                },
                {
                    "node_types": [
                        {
                            "kind": node_type,
                            "icon": config["icon"],
                            "color": config["color"],
                            "searchable_properties": config["searchable_properties"]
                        }
                        for node_type, config in self.gcp_node_types.items()
                    ]
                }
            ]
            
            endpoints = ["/api/v2/custom-nodes", "/api/v1/custom-nodes", "/api/custom-nodes"]
            
            for payload in bulk_payloads:
                for endpoint in endpoints:
                    try:
                        response = requests.post(
                            f"{self.bloodhound_url}{endpoint}",
                            headers=self.headers,
                            json=payload,
                            timeout=30
                        )
                        
                        if response.status_code in [200, 201]:
                            return True, f"Successfully registered {len(self.gcp_node_types)} GCP node types via bulk registration"
                            
                    except Exception:
                        continue
            
            return False, "All registration methods failed - BloodHound API may not support custom nodes"
            
        except Exception as e:
            return False, f"Bulk registration failed: {str(e)}"

def register_gcp_icons_and_search(bloodhound_url: str, token: str) -> bool:
    """Simple function to register GCP search nodes and enable search functionality
    
    Args:
        bloodhound_url: BloodHound instance URL
        token: BloodHound API token
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not token:
        logger.warning("No BloodHound token provided - skipping search registration")
        return False
        
    try:
        extension = GCPBloodHoundSearchExtension(bloodhound_url, token)
        
        # Test connection first
        if not extension.test_connection():
            logger.error("Failed to connect to BloodHound API")
            return False
        
        # Register GCP node types
        success, message = extension.register_gcp_node_types()
        if success:
            logger.info(f"GCP search registration: {message}")
            return True
        else:
            logger.error(f"Failed to register GCP nodes: {message}")
            return False
            
    except Exception as e:
        logger.error(f"Exception in GCP search registration: {e}")
        return False

# Example usage
if __name__ == "__main__":
    # Example configuration
    BLOODHOUND_URL = "http://localhost:8080"
    BLOODHOUND_TOKEN = "your-bloodhound-api-token"
    
    # Test basic registration
    success = register_gcp_icons_and_search(BLOODHOUND_URL, BLOODHOUND_TOKEN)
    if success:
        print("✅ GCP search registration successful!")
    else:
        print("❌ GCP search registration failed!")
