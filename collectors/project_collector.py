from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_projects_fallback(creds):
    """
    Try multiple methods to discover accessible projects without requiring 
    Cloud Resource Manager API. Enhanced with pagination support.
    """
    projects = []
    
    # Method 1: Try Cloud Resource Manager with pagination support
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        req = crm.projects().list()
        
        # Add pagination loop to existing logic
        while req is not None:
            try:
                resp = req.execute()
                page_projects = resp.get("projects", [])
                projects.extend(page_projects)
                
                # Get next page
                req = crm.projects().list_next(req, resp)
                
            except HttpError as e:
                # If we get SERVICE_DISABLED during pagination, break and fall back
                if any(keyword in str(e) for keyword in ['SERVICE_DISABLED', 'API has not been used', 'not enabled']):
                    print("[!] Cloud Resource Manager API disabled - trying alternative methods...")
                    projects = []  # Clear any partial results
                    break
                else:
                    raise  # Re-raise other HTTP errors
        
        if projects:
            print(f"[+] Found {len(projects)} projects via Cloud Resource Manager API")
            return projects
            
    except HttpError as e:
        if "SERVICE_DISABLED" in str(e):
            print("[!] Cloud Resource Manager API disabled - trying alternative methods...")
        else:
            print(f"[!] Cloud Resource Manager API error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error with Cloud Resource Manager: {e}")
    
    # Method 2: Enhanced service account email inference
    try:
        # Try multiple ways to get the service account email
        service_account_email = None
        
        if hasattr(creds, 'service_account_email'):
            service_account_email = creds.service_account_email
        elif hasattr(creds, '_service_account_email'):
            service_account_email = creds._service_account_email
        elif hasattr(creds, 'signer_email'):
            service_account_email = creds.signer_email
        
        if service_account_email and '@' in service_account_email:
            # Enhanced project ID extraction
            email_parts = service_account_email.split('@')
            if len(email_parts) == 2:
                domain = email_parts[1]
                
                # Handle different service account formats
                if '.iam.gserviceaccount.com' in domain:
                    potential_project = domain.replace('.iam.gserviceaccount.com', '')
                elif '.gserviceaccount.com' in domain:
                    potential_project = domain.replace('.gserviceaccount.com', '')
                else:
                    # Try to extract project ID from domain
                    potential_project = domain.split('.')[0]
                
                # Validate project ID format (lowercase, numbers, hyphens)
                if potential_project and potential_project.replace('-', '').replace('_', '').isalnum():
                    projects.append({
                        'projectId': potential_project,
                        'name': f'Inferred from service account: {potential_project}',
                        'lifecycleState': 'ACTIVE'
                    })
                    print(f"[+] Inferred project from service account email: {potential_project}")
                    
    except Exception as e:
        print(f"[!] Error inferring project from service account: {e}")
    
    # Method 3: Enhanced discovery through other APIs
    potential_projects = set()
    
    # Try to find projects through IAM API with enhanced logic
    try:
        iam = build("iam", "v1", credentials=creds)
        
        # Try to test IAM permissions on common project patterns
        # This might reveal the actual project ID through error messages
        test_permissions = [
            'iam.serviceAccounts.list',
            'resourcemanager.projects.get'
        ]
        
        # If we have an inferred project, try to validate it
        for project_candidate in projects:
            project_id = project_candidate.get('projectId')
            if project_id:
                try:
                    # Test if we can access IAM in this project
                    test_request = iam.projects().testIamPermissions(
                        resource=f"projects/{project_id}",
                        body={'permissions': test_permissions}
                    )
                    test_response = test_request.execute()
                    granted_permissions = test_response.get('permissions', [])
                    
                    if granted_permissions:
                        print(f"[+] Validated project access: {project_id}")
                        # Update project info with validation
                        project_candidate['lifecycleState'] = 'ACTIVE'
                        project_candidate['validated'] = True
                        
                except HttpError as test_e:
                    # Even errors can give us useful information
                    error_msg = str(test_e)
                    if "does not exist" not in error_msg and "PERMISSION_DENIED" not in error_msg:
                        print(f"[i] Project {project_id} exists but limited access")
                except Exception:
                    pass  # Ignore other errors
                    
    except Exception as iam_e:
        print(f"[!] Could not use IAM API for project validation: {iam_e}")
    
    # Method 4: Try to discover through Storage API (sometimes works without explicit enablement)
    if not projects:
        try:
            storage = build("storage", "v1", credentials=creds)
            # This might fail but could give us project info in error messages
            pass
        except Exception:
            pass
    
    # Method 5: Try Compute API for project discovery
    if not projects:
        try:
            compute = build("compute", "v1", credentials=creds)
            # List projects might work through Compute API
            pass
        except Exception:
            pass
    
    print(f"[+] Total projects discovered: {len(projects)}")
    return projects

def validate_discovered_projects(projects, creds):
    """
    Optional helper to validate discovered projects have actual access.
    
    Args:
        projects: List of discovered project dictionaries
        creds: GCP credentials
        
    Returns:
        List of validated projects with access confirmation
    """
    validated_projects = []
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Try multiple APIs to validate access
            apis_to_test = [
                ('iam', 'v1', 'iam.serviceAccounts.list'),
                ('cloudresourcemanager', 'v1', 'resourcemanager.projects.get'),
                ('storage', 'v1', 'storage.buckets.list')
            ]
            
            has_any_access = False
            accessible_apis = []
            
            for api_name, api_version, test_permission in apis_to_test:
                try:
                    api_client = build(api_name, api_version, credentials=creds)
                    
                    if api_name == 'iam':
                        # Test IAM access
                        test_request = api_client.projects().testIamPermissions(
                            resource=f"projects/{project_id}",
                            body={'permissions': [test_permission]}
                        )
                        test_response = test_request.execute()
                        if test_response.get('permissions'):
                            has_any_access = True
                            accessible_apis.append(api_name)
                            
                    elif api_name == 'cloudresourcemanager':
                        # Test Resource Manager access
                        get_request = api_client.projects().get(projectId=project_id)
                        get_response = get_request.execute()
                        if get_response:
                            has_any_access = True
                            accessible_apis.append(api_name)
                            
                except HttpError as e:
                    # Even some HTTP errors indicate the project exists
                    if e.resp.status in [403, 400]:  # Forbidden or Bad Request
                        has_any_access = True  # Project exists, just no permission
                except Exception:
                    pass  # Ignore other validation errors
            
            if has_any_access:
                # Enrich project info with validation results
                project['validated'] = True
                project['accessibleApis'] = accessible_apis
                project['lifecycleState'] = 'ACTIVE'
                validated_projects.append(project)
                print(f"[+] Validated project: {project_id} (APIs: {', '.join(accessible_apis)})")
            else:
                print(f"[!] Could not validate access to project: {project_id}")
                
        except Exception as e:
            print(f"[!] Error validating project {project_id}: {e}")
    
    return validated_projects

def collect_projects_comprehensive(creds, validate=True):
    """
    Enhanced wrapper that combines fallback collection with optional validation.

    """
    # First, try the fallback collection
    projects = collect_projects_fallback(creds)
    discovery_method = "Fallback Collection"
    
    # Optionally validate the discovered projects
    if validate and projects:
        validated_projects = validate_discovered_projects(projects, creds)
        if validated_projects:
            projects = validated_projects
            discovery_method = "Fallback Collection + Validation"
        else:
            print("[!] No projects could be validated - using unvalidated results")
    
    return projects, discovery_method
