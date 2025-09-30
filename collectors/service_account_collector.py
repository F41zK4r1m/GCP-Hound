from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_paginated_service_accounts(iam_client, project_name):
    """
    Generic helper to collect all paginated service accounts for a single project.
    
    Args:
        iam_client: Built IAM API client
        project_name: Full project resource name (e.g., 'projects/my-project')
    
    Returns:
        List of all service accounts from all pages
    """
    all_accounts = []
    request = iam_client.projects().serviceAccounts().list(name=project_name)
    page_count = 0
    
    while request is not None:
        try:
            response = request.execute()
            accounts = response.get('accounts', [])
            all_accounts.extend(accounts)
            page_count += 1
            
            # Get next page request
            request = iam_client.projects().serviceAccounts().list_next(
                previous_request=request, 
                previous_response=response
            )
            
        except Exception as e:
            print(f"[!] Error during service account pagination: {e}")
            break
    
    return all_accounts, page_count

def collect_service_accounts(creds, projects):
    """
    Collect service accounts from accessible projects with enhanced pagination and error handling.
    
    Args:
        creds: Google Cloud credentials
        projects: List of project dictionaries with 'projectId' key
    
    Returns:
        List of service account dictionaries with project context added
    """
    service_accounts = []
    total_projects_processed = 0
    total_accounts_found = 0
    
    print("[*] Starting service account enumeration with pagination...")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            print("[!] Skipping project with missing projectId")
            continue
            
        total_projects_processed += 1
        
        try:
            # Build IAM client for this project
            iam = build("iam", "v1", credentials=creds)
            project_name = f'projects/{project_id}'
            
            # Use pagination helper to get all service accounts
            accounts, page_count = collect_paginated_service_accounts(iam, project_name)
            
            # Add project context to each account
            for account in accounts:
                account['project'] = project_id
                account['projectName'] = project.get('name', project_id)  # Enhanced context
                service_accounts.append(account)
            
            total_accounts_found += len(accounts)
            
            # Enhanced logging with pagination info
            if accounts:
                pagination_info = f" ({page_count} pages)" if page_count > 1 else ""
                print(f"[+] Found {len(accounts)} service accounts in {project_id}")
            else:
                print(f"[i] No service accounts found in {project_id}")
                
        except HttpError as e:
            error_code = str(e.resp.status) if hasattr(e, 'resp') else "unknown"
            if "403" in str(e) or error_code == "403":
                print(f"[!] No IAM access to project {project_id} (403 Forbidden)")
            elif "404" in str(e) or error_code == "404":
                print(f"[!] Project {project_id} not found or deleted (404)")
            elif "API not enabled" in str(e):
                print(f"[!] IAM API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP error listing service accounts in {project_id}: {e}")
                
        except Exception as e:
            print(f"[!] Unexpected error with {project_id}: {e}")
    
    # Summary statistics
    print(f"[+] Service account enumeration complete: {total_accounts_found} accounts across {total_projects_processed} projects")
    
    return service_accounts

def analyze_service_account_privileges(service_accounts):
    """
    Optional: Analyze collected service accounts for privilege patterns and risk assessment.
    """
    if not service_accounts:
        return {"total": 0, "analysis": "No service accounts to analyze"}
    
    analysis = {
        "total": len(service_accounts),
        "by_project": {},
        "google_managed": 0,
        "user_managed": 0,
        "disabled": 0
    }
    
    for sa in service_accounts:
        project_id = sa.get('project', 'unknown')
        email = sa.get('email', '')
        disabled = sa.get('disabled', False)
        
        # Count by project
        analysis["by_project"][project_id] = analysis["by_project"].get(project_id, 0) + 1
        
        # Categorize service account types
        if 'compute@developer.gserviceaccount.com' in email or 'service-' in email:
            analysis["google_managed"] += 1
        else:
            analysis["user_managed"] += 1
            
        # Count disabled accounts
        if disabled:
            analysis["disabled"] += 1
    
    return analysis

def collect_service_accounts_with_analysis(creds, projects, include_analysis=True):
    """
    Enhanced wrapper that collects service accounts and optionally provides analysis.
    
    Args:
        creds: Google Cloud credentials
        projects: List of project dictionaries
        include_analysis: Whether to perform privilege analysis (default: True)
    
    Returns:
        Tuple of (service_accounts_list, analysis_dict)
    """
    service_accounts = collect_service_accounts(creds, projects)
    
    analysis = None
    if include_analysis and service_accounts:
        analysis = analyze_service_account_privileges(service_accounts)
        
        # Print analysis summary
        print(f"\n[*] Service Account Analysis:")
        print(f"    Total: {analysis['total']}")
        print(f"    Google-managed: {analysis['google_managed']}")
        print(f"    User-managed: {analysis['user_managed']}")
        print(f"    Disabled: {analysis['disabled']}")
        print(f"    Projects with SAs: {len(analysis['by_project'])}")
    
    return service_accounts, analysis
