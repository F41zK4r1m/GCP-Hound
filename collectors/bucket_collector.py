from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_paginated_buckets(storage_client, project_id):
    """
    Helper function to collect all paginated buckets for a single project.
    
    Args:
        storage_client: Built Storage API client
        project_id: GCP project ID to list buckets from
    
    Returns:
        Tuple of (all_buckets_list, page_count)
    """
    all_buckets = []
    request = storage_client.buckets().list(project=project_id)
    page_count = 0
    
    while request is not None:
        try:
            response = request.execute()
            buckets = response.get('items', [])
            all_buckets.extend(buckets)
            page_count += 1
            
            # Get next page request
            request = storage_client.buckets().list_next(
                previous_request=request, 
                previous_response=response
            )
            
        except Exception as e:
            print(f"[!] Error during bucket pagination: {e}")
            break
    
    return all_buckets, page_count

def collect_buckets(creds, projects):
    """
    Enumerate all GCS storage buckets across accessible projects with enhanced pagination.
    Returns a list of bucket dicts with project context and security metadata.
    """
    buckets = []
    total_projects_processed = 0
    total_buckets_found = 0
    
    print("[*] Starting storage bucket enumeration...")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            print("[!] Skipping project with missing projectId")
            continue
            
        total_projects_processed += 1
        
        try:
            # Build Storage API client for this project
            storage = build("storage", "v1", credentials=creds)
            
            # Use pagination helper to get all buckets
            project_buckets, page_count = collect_paginated_buckets(storage, project_id)
            
            # Process each bucket and add enriched metadata
            for bucket in project_buckets:
                bucket_info = {
                    'name': bucket.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'location': bucket.get('location'),
                    'storageClass': bucket.get('storageClass'),
                    'versioning': bucket.get('versioning', {}).get('enabled', False),
                    'encryption': bucket.get('encryption', {}).get('defaultKmsKeyName'),
                    'publicAccess': bucket.get('iamConfiguration', {}).get('publicAccessPrevention'),
                    'uniformBucketAccess': bucket.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled', False),
                    'created': bucket.get('timeCreated'),
                    'updated': bucket.get('updated'),
                    'labels': bucket.get('labels', {}),
                    # Enhanced security analysis
                    'riskLevel': assess_bucket_risk_level(bucket),
                    'selfLink': bucket.get('selfLink'),
                    'etag': bucket.get('etag')
                }
                
                buckets.append(bucket_info)
            
            total_buckets_found += len(project_buckets)
            
            # Enhanced logging with pagination info (only for debug/verbose)
            if project_buckets:
                print(f"[+] Found {len(project_buckets)} storage buckets in {project_id}")
                
                # Print bucket details
                for bucket in project_buckets:
                    bucket_name = bucket.get('name')
                    location = bucket.get('location', 'unknown')
                    storage_class = bucket.get('storageClass', 'unknown')
                    
                    # Enhanced public access status
                    public_prevention = bucket.get('iamConfiguration', {}).get('publicAccessPrevention', 'unknown')
                    uniform_access = bucket.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled', False)
                    
                    access_status = "uniform" if uniform_access else f"public access: {public_prevention}"
                    print(f"    - {bucket_name} ({location}, {storage_class}, {access_status})")
            else:
                print(f"[i] No storage buckets found in {project_id}")
                
        except HttpError as e:
            error_code = str(e.resp.status) if hasattr(e, 'resp') else "unknown"
            if "403" in str(e) or error_code == "403":
                print(f"[!] No storage.buckets.list permission for project {project_id}")
            elif "404" in str(e) or error_code == "404":
                print(f"[!] Storage API not enabled for project {project_id}")
            elif "API not enabled" in str(e):
                print(f"[!] Google Cloud Storage JSON API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error listing buckets in {project_id}: {e}")
                
        except Exception as e:
            print(f"[!] Unexpected error listing buckets in {project_id}: {e}")
    
    # Summary statistics
    print(f"[+] Storage bucket enumeration complete: {total_buckets_found} buckets across {total_projects_processed} projects")
    
    return buckets

def assess_bucket_risk_level(bucket):
    """
    Assess the security risk level of a storage bucket based on configuration.
    
    Args:
        bucket: Raw bucket dictionary from GCS API
    
    Returns:
        Risk level string: 'HIGH', 'MEDIUM', 'LOW'
    """
    risk_factors = 0
    
    # Check public access prevention
    iam_config = bucket.get('iamConfiguration', {})
    public_prevention = iam_config.get('publicAccessPrevention')
    if public_prevention != 'enforced':
        risk_factors += 2  # Higher risk if public access not prevented
    
    # Check uniform bucket-level access
    uniform_access = iam_config.get('uniformBucketLevelAccess', {}).get('enabled', False)
    if not uniform_access:
        risk_factors += 1  # ACLs can be complex and risky
    
    # Check versioning
    versioning = bucket.get('versioning', {}).get('enabled', False)
    if not versioning:
        risk_factors += 1  # No protection against accidental deletion/modification
    
    # Check encryption
    encryption = bucket.get('encryption', {}).get('defaultKmsKeyName')
    if not encryption:
        risk_factors += 1  # Using Google-managed keys instead of CMEK
    
    # Check lifecycle management
    lifecycle = bucket.get('lifecycle')
    if not lifecycle:
        risk_factors += 1  # No automated cleanup/archival
    
    # Assess overall risk
    if risk_factors >= 4:
        return 'HIGH'
    elif risk_factors >= 2:
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_bucket_access_patterns(buckets, service_accounts):

    if not buckets:
        return {"total": 0, "analysis": "No buckets to analyze"}
    
    analysis = {
        "total": len(buckets),
        "by_project": {},
        "by_location": {},
        "high_risk": 0,
        "public_buckets": 0,
        "encrypted_buckets": 0
    }
    
    for bucket in buckets:
        project_id = bucket.get('project', 'unknown')
        location = bucket.get('location', 'unknown')
        risk_level = bucket.get('riskLevel', 'LOW')
        
        # Count by project and location
        analysis["by_project"][project_id] = analysis["by_project"].get(project_id, 0) + 1
        analysis["by_location"][location] = analysis["by_location"].get(location, 0) + 1
        
        # Risk analysis
        if risk_level == 'HIGH':
            analysis["high_risk"] += 1
            
        # Public access analysis
        if bucket.get('publicAccess') != 'enforced':
            analysis["public_buckets"] += 1
            
        # Encryption analysis
        if bucket.get('encryption'):
            analysis["encrypted_buckets"] += 1
    
    return analysis
