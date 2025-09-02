from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import time

class TerminalColors:
    """ANSI color codes for colorful terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def colorize(text, color):
    """Add color to text for terminal output"""
    return f"{color}{text}{TerminalColors.RESET}"

def discover_projects_comprehensive(creds):
    """
    Comprehensive project discovery using multiple methods.
    Returns list of projects and discovery method used.
    """
    projects = []
    discovery_method = None
    
    # Method 1: Try Cloud Resource Manager API
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        request = crm.projects().list()
        response = request.execute()
        projects = response.get('projects', [])
        
        if projects:
            discovery_method = "Cloud Resource Manager API"
            print(f"[+] Discovered {len(projects)} projects via Cloud Resource Manager API")
            for project in projects:
                project_id = project.get('projectId')
                project_name = project.get('name', project_id)
                print(f"    - {project_name} ({project_id})")
            return projects, discovery_method
            
    except HttpError as e:
        print(f"[!] Cloud Resource Manager API disabled - using fallback methods")
    except Exception as e:
        print(f"[!] Error with Cloud Resource Manager API: {e}")
    
    # Method 2: Infer from service account email
    try:
        from utils.auth import get_active_account
        user_email = get_active_account(creds)
        
        if '@' in user_email:
            # Extract project from service account email
            email_parts = user_email.split('@')
            if len(email_parts) == 2:
                domain = email_parts[1]
                if '.iam.gserviceaccount.com' in domain:
                    project_id = domain.replace('.iam.gserviceaccount.com', '')
                    
                    # Create project object
                    inferred_project = {
                        'projectId': project_id,
                        'name': project_id,
                        'lifecycleState': 'ACTIVE'
                    }
                    
                    projects = [inferred_project]
                    discovery_method = "Service Account Email Inference"
                    print(f"[+] Inferred project from service account: {project_id}")
                    return projects, discovery_method
                    
    except Exception as e:
        print(f"[!] Error inferring project from service account: {e}")
    
    # Method 3: Try to enumerate via IAM (if we have permissions)
    try:
        iam = build("iam", "v1", credentials=creds)
        # This might help discover projects indirectly
        pass
    except Exception:
        pass
    
    return projects, discovery_method

def discover_apis_for_projects(creds, projects):
    """
    Discover enabled APIs for each project.
    Returns dict mapping project IDs to enabled APIs.
    """
    project_apis = {}
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            serviceusage = build("serviceusage", "v1", credentials=creds)
            request = serviceusage.services().list(
                parent=f"projects/{project_id}",
                filter="state:ENABLED"
            )
            response = request.execute()
            
            enabled_services = response.get('services', [])
            api_names = []
            
            for service in enabled_services:
                service_name = service.get('config', {}).get('name', '')
                if service_name:
                    api_names.append(service_name)
            
            project_apis[project_id] = api_names
            print(f"[+] Found {colorize(str(len(api_names)), TerminalColors.WHITE)} enabled APIs in {colorize(project_id, TerminalColors.CYAN)}")
            
        except HttpError as e:
            print(f"[!] Error listing APIs for {project_id}: {e}")
            project_apis[project_id] = []
        except Exception as e:
            print(f"[!] Unexpected error for {project_id}: {e}")
            project_apis[project_id] = []
    
    return project_apis

def assess_enumeration_capabilities(project_apis):
    """
    Assess enumeration capabilities based on enabled APIs and permissions.
    Returns capabilities dict and enriched project data.
    """
    print(f"\n{colorize('[*] Enumeration Capabilities by Project:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    
    capabilities = {
        "Service Accounts": False,
        "Storage Buckets": False,
        "Users/Groups": "conditional",  # UPDATED: Changed to conditional
        "Compute Instances": False,
        "Secrets": False,
        "BigQuery": False,
        "GKE Clusters": False,
        "Cloud Functions": False
    }
    
    enriched_project_data = {}
    
    for project_id, apis in project_apis.items():
        print(f"\n    {colorize('Project:', TerminalColors.BLUE)} {colorize(project_id, TerminalColors.WHITE)}")
        
        project_capabilities = {}
        
        # Check IAM API for Service Accounts
        if any('iam.googleapis.com' in api for api in apis):
            capabilities["Service Accounts"] = True
            project_capabilities["Service Accounts"] = True
            print(f"      {colorize('Service Accounts', TerminalColors.GREEN)}   ✓")
        else:
            project_capabilities["Service Accounts"] = False
            print(f"      {colorize('Service Accounts', TerminalColors.RED)}   ✗")
        
        # Check Storage API for Buckets
        if any('storage-api.googleapis.com' in api or 'storage.googleapis.com' in api for api in apis):
            capabilities["Storage Buckets"] = True
            project_capabilities["Storage Buckets"] = True
            print(f"      {colorize('Storage Buckets', TerminalColors.GREEN)}    ✓")
        else:
            project_capabilities["Storage Buckets"] = False
            print(f"      {colorize('Storage Buckets', TerminalColors.RED)}    ✗")
        
        # Admin SDK for Users/Groups (conditional)
        if any('admin.googleapis.com' in api for api in apis):
            project_capabilities["Users/Groups"] = "conditional"
            print(f"      {colorize('Users/Groups', TerminalColors.YELLOW)}       ✓")
        else:
            project_capabilities["Users/Groups"] = False
            print(f"      {colorize('Users/Groups', TerminalColors.RED)}       ✗")
        
        # Check Compute API for Instances
        if any('compute.googleapis.com' in api for api in apis):
            capabilities["Compute Instances"] = True
            project_capabilities["Compute Instances"] = True
            print(f"      {colorize('Compute Instances', TerminalColors.GREEN)}  ✓")
        else:
            project_capabilities["Compute Instances"] = False
            print(f"      {colorize('Compute Instances', TerminalColors.RED)}  ✗")
        
        # Check Secret Manager API
        if any('secretmanager.googleapis.com' in api for api in apis):
            capabilities["Secrets"] = True
            project_capabilities["Secrets"] = True
            print(f"      {colorize('Secrets', TerminalColors.GREEN)}            ✓")
        else:
            project_capabilities["Secrets"] = False
            print(f"      {colorize('Secrets', TerminalColors.RED)}            ✗")
        
        # Check BigQuery API
        if any('bigquery.googleapis.com' in api for api in apis):
            capabilities["BigQuery"] = True
            project_capabilities["BigQuery"] = True
            print(f"      {colorize('BigQuery', TerminalColors.GREEN)}           ✓")
        else:
            project_capabilities["BigQuery"] = False
            print(f"      {colorize('BigQuery', TerminalColors.RED)}           ✗")
        
        # Check Container API for GKE Clusters
        if any('container.googleapis.com' in api for api in apis):
            capabilities["GKE Clusters"] = True
            project_capabilities["GKE Clusters"] = True
            print(f"      {colorize('GKE Clusters', TerminalColors.GREEN)}       ✓")
        else:
            project_capabilities["GKE Clusters"] = False
            print(f"      {colorize('GKE Clusters', TerminalColors.RED)}       ✗")
        
        # Check Cloud Functions API
        if any('cloudfunctions.googleapis.com' in api for api in apis):
            capabilities["Cloud Functions"] = True
            project_capabilities["Cloud Functions"] = True
            print(f"      {colorize('Cloud Functions', TerminalColors.GREEN)}    ✓")
        else:
            project_capabilities["Cloud Functions"] = False
            print(f"      {colorize('Cloud Functions', TerminalColors.RED)}    ✗")
        
        enriched_project_data[project_id] = {
            'project_id': project_id,
            'enabled_apis': apis,
            'capabilities': project_capabilities
        }
    
    # Calculate overall coverage
    available_collectors = sum(1 for v in capabilities.values() if v is True or v == "conditional")
    total_collectors = len(capabilities)
    
    print(f"\n{colorize('[+] Overall Enumeration Coverage:', TerminalColors.GREEN + TerminalColors.BOLD)} {available_collectors}/{total_collectors} collectors available")
    
    return capabilities, enriched_project_data
