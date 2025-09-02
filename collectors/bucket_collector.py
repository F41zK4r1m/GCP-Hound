from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_buckets(creds, projects):
    """
    Enumerate all GCS storage buckets across accessible projects.
    Returns a list of bucket dicts with project context.
    """
    buckets = []
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Storage API client
            storage = build("storage", "v1", credentials=creds)
            
            # List buckets in this project
            request = storage.buckets().list(project=project_id)
            
            while request is not None:
                response = request.execute()
                project_buckets = response.get('items', [])
                
                for bucket in project_buckets:
                    # Enrich bucket data with project context
                    bucket['project'] = project_id
                    bucket['projectName'] = project.get('name', project_id)
                    
                    # Add useful metadata
                    bucket_info = {
                        'name': bucket.get('name'),
                        'project': project_id,
                        'location': bucket.get('location'),
                        'storageClass': bucket.get('storageClass'),
                        'versioning': bucket.get('versioning', {}).get('enabled', False),
                        'encryption': bucket.get('encryption', {}).get('defaultKmsKeyName'),
                        'publicAccess': bucket.get('iamConfiguration', {}).get('publicAccessPrevention'),
                        'uniformBucketAccess': bucket.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled', False),
                        'created': bucket.get('timeCreated'),
                        'updated': bucket.get('updated'),
                        'labels': bucket.get('labels', {}),
                        'projectName': project.get('name', project_id)
                    }
                    
                    buckets.append(bucket_info)
                
                # Handle pagination
                request = storage.buckets().list_next(
                    previous_request=request, previous_response=response)
                
            if project_buckets:
                print(f"[+] Found {len(project_buckets)} storage buckets in {project_id}")
                for bucket in project_buckets:
                    bucket_name = bucket.get('name')
                    location = bucket.get('location', 'unknown')
                    storage_class = bucket.get('storageClass', 'unknown')
                    public_prevention = bucket.get('iamConfiguration', {}).get('publicAccessPrevention', 'unknown')
                    print(f"    - {bucket_name} ({location}, {storage_class}, public access: {public_prevention})")
            else:
                print(f"[~] No storage buckets found in {project_id}")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No storage.buckets.list permission for project {project_id}")
            elif error_code == 404:
                print(f"[!] Storage API not found/enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error listing buckets in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error listing buckets in {project_id}: {e}")
    
    print(f"[+] Total storage buckets discovered: {len(buckets)}")
    return buckets
