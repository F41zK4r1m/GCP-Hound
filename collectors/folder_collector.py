from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_folders(creds, orgs):
    """
    Enumerate folders and organizational hierarchy from Google Cloud.
    Works with Cloud Resource Manager API (no admin SDK required).
    """
    folders = []
    folder_hierarchy = {}
    
    if not creds:
        print("[!] No credentials provided to folder collector")
        return folders, folder_hierarchy
    
    if not orgs:
        print("[!] No organizations provided - discovering accessible folders")
        return discover_accessible_folders(creds)
    
    try:
        # Build Cloud Resource Manager service
        crm_service = build('cloudresourcemanager', 'v1', credentials=creds)
        
        print(f"[*] Folder Collector: Enumerating folders for {len(orgs)} organizations...")
        
        for org in orgs:
            org_id = org.get('name', '').replace('organizations/', '')
            org_display_name = org.get('displayName', org_id)
            
            if org_id:
                print(f"[*] Analyzing organization: {org_display_name} ({org_id})")
                
                # Collect folders for this organization
                org_folders = collect_org_folders(crm_service, org_id)
                folders.extend(org_folders)
                
                # Build hierarchy mapping
                org_hierarchy = build_folder_hierarchy(org_folders, org_id)
                folder_hierarchy[org_id] = org_hierarchy
        
        print(f"[+] Folder Collector: Found {len(folders)} folders across {len(orgs)} organizations")
        
    except HttpError as e:
        if e.resp.status == 403:
            print("[!] Limited folder access - trying alternative discovery")
            return discover_accessible_folders(creds)
        else:
            print(f"[!] HTTP error during folder collection: {e}")
    except Exception as e:
        print(f"[!] Unexpected error during folder collection: {e}")
    
    return folders, folder_hierarchy

def collect_org_folders(crm_service, org_id):
    """Recursively collect all folders under an organization"""
    folders = []
    
    try:
        # Start with organization as parent
        parent_id = f"organizations/{org_id}"
        folders = recursive_folder_discovery(crm_service, parent_id)
        
        print(f"[+] Found {len(folders)} folders in organization {org_id}")
        
    except Exception as e:
        print(f"[!] Error collecting folders for organization {org_id}: {e}")
    
    return folders

def recursive_folder_discovery(crm_service, parent_id, depth=0):
    """Recursively discover folders starting from a parent"""
    folders = []
    max_depth = 10  # Prevent infinite recursion
    
    if depth > max_depth:
        print(f"[!] Maximum folder depth ({max_depth}) reached for parent {parent_id}")
        return folders
    
    try:
        # Use Cloud Resource Manager v2 for folder operations
        crm_v2 = build('cloudresourcemanager', 'v2', credentials=crm_service._http.credentials)
        
        request = crm_v2.folders().list(parent=parent_id)
        
        while request:
            response = request.execute()
            
            for folder in response.get('folders', []):
                folder_data = {
                    'id': folder.get('name', '').replace('folders/', ''),
                    'name': folder.get('name', ''),
                    'displayName': folder.get('displayName', ''),
                    'parent': folder.get('parent', ''),
                    'lifecycleState': folder.get('lifecycleState', ''),
                    'createTime': folder.get('createTime', ''),
                    'updateTime': folder.get('updateTime', ''),
                    'depth': depth,
                    'parentType': determine_parent_type(folder.get('parent', ''))
                }
                
                # Analyze security context
                folder_data['riskLevel'] = determine_folder_risk_level(folder_data)
                folder_data['securityContext'] = analyze_folder_security_context(folder_data)
                
                folders.append(folder_data)
                
                # Recursively get child folders
                folder_name = folder.get('name', '')
                if folder_name:
                    child_folders = recursive_folder_discovery(crm_service, folder_name, depth + 1)
                    folders.extend(child_folders)
            
            # Check for next page
            request = crm_v2.folders().list_next(request, response)
            
    except HttpError as e:
        if e.resp.status != 403:  # Ignore permission denied, expected for some folders
            print(f"[!] Error discovering folders under {parent_id}: {e}")
    except Exception as e:
        print(f"[!] Unexpected error discovering folders under {parent_id}: {e}")
    
    return folders

def discover_accessible_folders(creds):
    """Discover folders accessible to current credentials (fallback method)"""
    folders = []
    folder_hierarchy = {}
    
    try:
        crm_v2 = build('cloudresourcemanager', 'v2', credentials=creds)
        
        print("[*] Attempting to discover accessible folders via search...")
        
        # Search for all accessible folders
        request = crm_v2.folders().search(body={})
        
        while request:
            response = request.execute()
            
            for folder in response.get('folders', []):
                folder_data = {
                    'id': folder.get('name', '').replace('folders/', ''),
                    'name': folder.get('name', ''),
                    'displayName': folder.get('displayName', ''),
                    'parent': folder.get('parent', ''),
                    'lifecycleState': folder.get('lifecycleState', ''),
                    'createTime': folder.get('createTime', ''),
                    'updateTime': folder.get('updateTime', ''),
                    'parentType': determine_parent_type(folder.get('parent', '')),
                    'discoveryMethod': 'search'
                }
                
                folder_data['riskLevel'] = determine_folder_risk_level(folder_data)
                folder_data['securityContext'] = analyze_folder_security_context(folder_data)
                
                folders.append(folder_data)
            
            request = crm_v2.folders().search_next(request, response)
        
        print(f"[+] Discovered {len(folders)} accessible folders via search")
        
        # Build hierarchy from discovered folders
        folder_hierarchy = build_hierarchy_from_discovered_folders(folders)
        
    except Exception as e:
        print(f"[!] Error during accessible folder discovery: {e}")
    
    return folders, folder_hierarchy

def build_folder_hierarchy(folders, org_id):
    """Build hierarchical structure from folder list"""
    hierarchy = {
        'organization': org_id,
        'rootFolders': [],
        'folderMap': {},
        'parentChildMap': {}
    }
    
    # Create folder map for quick lookup
    for folder in folders:
        folder_id = folder.get('id')
        hierarchy['folderMap'][folder_id] = folder
        
        parent = folder.get('parent', '')
        if parent not in hierarchy['parentChildMap']:
            hierarchy['parentChildMap'][parent] = []
        hierarchy['parentChildMap'][parent].append(folder_id)
    
    # Identify root folders (direct children of organization)
    org_parent = f"organizations/{org_id}"
    hierarchy['rootFolders'] = hierarchy['parentChildMap'].get(org_parent, [])
    
    print(f"[+] Built hierarchy with {len(hierarchy['rootFolders'])} root folders")
    return hierarchy

def build_hierarchy_from_discovered_folders(folders):
    """Build hierarchy from folders discovered via search"""
    hierarchy = {
        'discoveredFolders': len(folders),
        'folderMap': {},
        'parentChildMap': {},
        'organizationRoots': {}
    }
    
    for folder in folders:
        folder_id = folder.get('id')
        parent = folder.get('parent', '')
        
        hierarchy['folderMap'][folder_id] = folder
        
        if parent not in hierarchy['parentChildMap']:
            hierarchy['parentChildMap'][parent] = []
        hierarchy['parentChildMap'][parent].append(folder_id)
        
        # Track organization roots
        if parent.startswith('organizations/'):
            org_id = parent.replace('organizations/', '')
            if org_id not in hierarchy['organizationRoots']:
                hierarchy['organizationRoots'][org_id] = []
            hierarchy['organizationRoots'][org_id].append(folder_id)
    
    return hierarchy

def determine_parent_type(parent_string):
    """Determine the type of parent resource"""
    if parent_string.startswith('organizations/'):
        return 'organization'
    elif parent_string.startswith('folders/'):
        return 'folder'
    else:
        return 'unknown'

def determine_folder_risk_level(folder_data):
    """Determine risk level for a folder based on naming and context"""
    display_name = folder_data.get('displayName', '').lower()
    
    high_risk_keywords = [
        'prod', 'production', 'security', 'admin', 'root', 
        'master', 'critical', 'infrastructure', 'shared'
    ]
    
    medium_risk_keywords = [
        'dev', 'development', 'test', 'staging', 'qa',
        'sandbox', 'experiment', 'trial'
    ]
    
    if any(keyword in display_name for keyword in high_risk_keywords):
        return 'HIGH'
    elif any(keyword in display_name for keyword in medium_risk_keywords):
        return 'MEDIUM'
    elif folder_data.get('depth', 0) == 0:  # Root folders
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_folder_security_context(folder_data):
    """Analyze security context of a folder"""
    context = {
        'isRootFolder': folder_data.get('parentType') == 'organization',
        'hierarchyDepth': folder_data.get('depth', 0),
        'namingPattern': classify_naming_pattern(folder_data.get('displayName', '')),
        'lifecycleState': folder_data.get('lifecycleState', ''),
        'hasSubfolders': False,  # Will be determined during hierarchy building
        'securityImplications': []
    }
    
    # Add security implications based on context
    if context['isRootFolder']:
        context['securityImplications'].append('Root-level folder with organization-wide impact')
    
    if context['hierarchyDepth'] > 5:
        context['securityImplications'].append('Deep nesting may indicate complex permissions')
    
    naming_risks = {
        'production': 'Production environment folder requires strict access control',
        'security': 'Security-related folder with elevated risk profile',
        'shared': 'Shared folder may have broad access permissions'
    }
    
    for pattern, implication in naming_risks.items():
        if pattern in folder_data.get('displayName', '').lower():
            context['securityImplications'].append(implication)
    
    return context

def classify_naming_pattern(display_name):
    """Classify folder naming pattern for security analysis"""
    name_lower = display_name.lower()
    
    if any(env in name_lower for env in ['prod', 'production']):
        return 'production'
    elif any(env in name_lower for env in ['dev', 'development', 'test', 'staging']):
        return 'non_production'
    elif any(func in name_lower for func in ['security', 'admin', 'infra']):
        return 'infrastructure'
    elif any(team in name_lower for team in ['team', 'dept', 'division']):
        return 'organizational'
    else:
        return 'generic'

def build_folder_edges(folders, folder_hierarchy, projects):
    """Build BloodHound edges for folder relationships"""
    edges = []
    
    # Folder containment edges
    for folder in folders:
        folder_id = folder.get('id')
        folder_name = folder.get('name')
        parent = folder.get('parent', '')
        
        if parent and folder_name:
            edge = {
                "start": {"value": parent},
                "end": {"value": folder_name},
                "kind": "Contains",
                "properties": {
                    "source": "folder_hierarchy",
                    "riskLevel": folder.get('riskLevel', 'LOW'),
                    "folderType": folder.get('securityContext', {}).get('namingPattern', 'generic'),
                    "hierarchyDepth": folder.get('depth', 0),
                    "description": f"Folder {folder.get('displayName')} is contained in {parent}"
                }
            }
            edges.append(edge)
    
    # Project-to-folder edges (if we can determine project parents)
    for project in projects:
        project_id = project.get('projectId')
        parent = project.get('parent', {})
        
        if parent and parent.get('type') == 'folder':
            folder_id = parent.get('id')
            
            edge = {
                "start": {"value": f"folders/{folder_id}"},
                "end": {"value": project_id},
                "kind": "Contains",
                "properties": {
                    "source": "project_folder_relationship",
                    "riskLevel": "MEDIUM",
                    "resourceType": "Project",
                    "description": f"Folder contains project {project_id}"
                }
            }
            edges.append(edge)
    
    print(f"[+] Built {len(edges)} folder relationship edges")
    return edges
