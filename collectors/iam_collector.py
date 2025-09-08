from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_iam(creds, projects, args=None):
    """
    Enumerate IAM policies and bindings across all accessible projects.
    Returns comprehensive IAM data for security analysis.
    """
    iam_data = []
    
    if not creds or not projects:
        if args and args.debug:
            print("[DEBUG] No credentials or projects provided to IAM collector")
        return iam_data
    
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        if args and args.verbose:
            print(f"[*] IAM Collector: Analyzing {len(projects)} projects for IAM bindings...")
        
        for project in projects:
            project_id = project.get("projectId")
            if not project_id:
                continue
            
            try:
                # Get IAM policy for the project
                policy = crm.projects().getIamPolicy(
                    resource=project_id,
                    body={}
                ).execute()
                
                bindings = policy.get("bindings", [])
                
                if bindings:
                    iam_data.append({
                        "projectId": project_id,
                        "projectName": project.get("name", project_id),
                        "bindings": bindings,
                        "bindingCount": len(bindings),
                        "etag": policy.get("etag", ""),
                        "version": policy.get("version", 1)
                    })
                    if args and args.verbose:
                        print(f"[+] Found {len(bindings)} IAM bindings in project: {project_id}")
                else:
                    if args and args.verbose:
                        print(f"[~] No IAM bindings found in project: {project_id}")
                    
            except HttpError as e:
                if args and args.debug:
                    if e.resp.status == 403:
                        print(f"[DEBUG] Permission denied for project {project_id}: {e}")
                    elif e.resp.status == 404:
                        print(f"[DEBUG] Project not found {project_id}: {e}")
                    else:
                        print(f"[DEBUG] HTTP error for project {project_id}: {e}")
                elif "SERVICE_DISABLED" in str(e) or "Cloud Resource Manager API" in str(e):
                    if args and args.verbose:
                        print(f"[!] IAM policy enumeration: API not enabled for {project_id}")
                elif e.resp.status == 403:
                    if args and args.verbose:
                        print(f"[!] IAM policy enumeration: Insufficient permissions for {project_id}")
            except Exception as e:
                if args and args.debug:
                    print(f"[DEBUG] Unexpected error for project {project_id}: {e}")
                elif args and args.verbose:
                    print(f"[!] IAM enumeration error for {project_id}")
                
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] Failed to initialize Cloud Resource Manager: {e}")
        elif args and args.verbose:
            print("[!] IAM enumeration: Failed to initialize service")
    
    if args and args.verbose:
        print(f"[+] IAM Collector: Completed analysis of {len(iam_data)} projects with IAM data")
    return iam_data

def analyze_cross_project_permissions(creds, current_user, projects, args=None):
    """
    Analyze what external resources the current user can control.
    This data will populate the "Outbound Object Control" section.
    """
    outbound_controls = []
    
    if not creds or not current_user or not projects:
        return outbound_controls
    
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        
        # Key permissions that indicate outbound control capabilities
        test_permissions = [
            # Storage permissions
            'storage.buckets.create',
            'storage.buckets.delete', 
            'storage.objects.create',
            'storage.objects.delete',
            
            # Compute permissions
            'compute.instances.start',
            'compute.instances.stop',
            'compute.instances.create',
            'compute.instances.delete',
            
            # IAM permissions (most critical for lateral movement)
            'iam.serviceAccounts.actAs',
            'iam.serviceAccounts.getAccessToken',
            'iam.serviceAccounts.create',
            
            # BigQuery permissions
            'bigquery.datasets.create',
            'bigquery.datasets.get',
            'bigquery.jobs.create',
            
            # Project-level permissions
            'resourcemanager.projects.get',
            'resourcemanager.projects.list'
        ]
        
        if args and args.verbose:
            print(f"[*] Testing {len(test_permissions)} permissions across {len(projects)} projects...")
        
        for project in projects:
            project_id = project.get('projectId')
            if not project_id:
                continue
                
            try:
                # Test permissions for this project
                result = crm.projects().testIamPermissions(
                    resource=project_id,
                    body={'permissions': test_permissions}
                ).execute()
                
                granted_permissions = result.get('permissions', [])
                
                if granted_permissions:
                    outbound_controls.append({
                        'projectId': project_id,
                        'projectName': project.get('name', project_id),
                        'permissions': granted_permissions,
                        'permissionCount': len(granted_permissions),
                        'riskLevel': 'CRITICAL' if any('iam' in p for p in granted_permissions) else 'HIGH'
                    })
                    
                    if args and args.verbose:
                        print(f"[+] User has {len(granted_permissions)} permissions in project: {project_id}")
                    
                    # Log critical permissions
                    critical_perms = [p for p in granted_permissions if 'iam' in p or 'create' in p]
                    if critical_perms and args and args.verbose:
                        print(f"    🚨 CRITICAL permissions: {', '.join(critical_perms)}")
                        
            except HttpError as e:
                if args and args.debug:
                    print(f"[DEBUG] Error testing permissions for project {project_id}: {e}")
                elif e.resp.status != 403 and args and args.verbose:  # Ignore permission denied
                    print(f"[!] Permission testing error for {project_id}")
            except Exception as e:
                if args and args.debug:
                    print(f"[DEBUG] Unexpected error testing project {project_id}: {e}")
                
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] Failed to analyze cross-project permissions: {e}")
        elif args and args.verbose:
            print("[!] Cross-project permission analysis failed")
    
    if args and args.verbose:
        print(f"[+] Found outbound control capabilities in {len(outbound_controls)} projects")
    return outbound_controls
