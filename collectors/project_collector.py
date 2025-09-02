from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_projects_fallback(creds):
    """
    Try multiple methods to discover accessible projects without requiring 
    Cloud Resource Manager API.
    """
    projects = []
    
    # Method 1: Try Cloud Resource Manager (might fail)
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        req = crm.projects().list()
        resp = req.execute()
        projects += resp.get("projects", [])
        print(f"[+] Found {len(projects)} projects via Cloud Resource Manager API")
        return projects
    except HttpError as e:
        if "SERVICE_DISABLED" in str(e):
            print("[!] Cloud Resource Manager API disabled - trying alternative methods...")
        else:
            print(f"[!] Cloud Resource Manager API error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error with Cloud Resource Manager: {e}")
    
    # Method 2: Extract project from service account email
    if hasattr(creds, 'service_account_email'):
        email = creds.service_account_email
        if '@' in email:
            potential_project = email.split('@')[1].split('.')[0]
            projects.append({
                'projectId': potential_project,
                'name': f'Inferred from service account: {potential_project}',
                'lifecycleState': 'UNKNOWN'
            })
            print(f"[+] Inferred project from service account email: {potential_project}")
    
    # Method 3: Try common project discovery through other APIs
    # We'll try APIs that might work without explicit enablement
    potential_projects = set()
    
    # Try to find projects through IAM API (sometimes works)
    try:
        iam = build("iam", "v1", credentials=creds)
        # This might give us project info in error messages or responses
        pass  # We'll implement this if needed
    except:
        pass
    
    print(f"[+] Total projects discovered: {len(projects)}")
    return projects
