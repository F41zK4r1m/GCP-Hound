from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_iam(creds, projects):
    """
    Enumerate IAM policies and bindings across all accessible projects.
    Returns comprehensive IAM data for security analysis.
    """
    iam_data = []
    
    if not creds or not projects:
        print("[!] No credentials or projects provided to IAM collector")
        return iam_data
    
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
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
                    print(f"[+] Found {len(bindings)} IAM bindings in project: {project_id}")
                else:
                    print(f"[~] No IAM bindings found in project: {project_id}")
                    
            except HttpError as e:
                if e.resp.status == 403:
                    print(f"[!] Permission denied for project {project_id}: {e}")
                elif e.resp.status == 404:
                    print(f"[!] Project not found {project_id}: {e}")
                else:
                    print(f"[!] HTTP error for project {project_id}: {e}")
            except Exception as e:
                print(f"[!] Unexpected error for project {project_id}: {e}")
                
    except Exception as e:
        print(f"[!] Failed to initialize Cloud Resource Manager: {e}")
    
    print(f"[+] IAM Collector: Completed analysis of {len(iam_data)} projects with IAM data")
    return iam_data

def analyze_cross_project_permissions(creds, current_user, projects):
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
                    
                    print(f"[+] User has {len(granted_permissions)} permissions in project: {project_id}")
                    
                    # Log critical permissions
                    critical_perms = [p for p in granted_permissions if 'iam' in p or 'create' in p]
                    if critical_perms:
                        print(f"    🚨 CRITICAL permissions: {', '.join(critical_perms)}")
                        
            except HttpError as e:
                if e.resp.status != 403:  # Ignore permission denied, expected for many projects
                    print(f"[!] Error testing permissions for project {project_id}: {e}")
            except Exception as e:
                print(f"[!] Unexpected error testing project {project_id}: {e}")
                
    except Exception as e:
        print(f"[!] Failed to analyze cross-project permissions: {e}")
    
    print(f"[+] Found outbound control capabilities in {len(outbound_controls)} projects")
    return outbound_controls
