from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_service_accounts(creds, projects):
    """
    Collect service accounts from accessible projects.
    """
    service_accounts = []
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            iam = build("iam", "v1", credentials=creds)
            request = iam.projects().serviceAccounts().list(name=f'projects/{project_id}')
            
            while request is not None:
                response = request.execute()
                accounts = response.get('accounts', [])
                for account in accounts:
                    account['project'] = project_id  # Add project context
                    service_accounts.append(account)
                
                request = iam.projects().serviceAccounts().list_next(
                    previous_request=request, previous_response=response)
            
            if accounts:
                print(f"[+] Found {len(accounts)} service accounts in {project_id}")
                
        except HttpError as e:
            if "403" in str(e):
                print(f"[!] No IAM access to project {project_id}")
            else:
                print(f"[!] Error listing service accounts in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error with {project_id}: {e}")
    
    return service_accounts
