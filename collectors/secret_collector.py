from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

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

def collect_secrets(creds, projects):
    """
    Enumerate all Secret Manager secrets across accessible projects.
    Returns a list of secret dicts with security analysis.
    """
    secrets = []
    
    print(f"\n{colorize('[*] ENUMERATING SECRET MANAGER SECRETS...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Secret Manager API client
            secretmanager = build("secretmanager", "v1", credentials=creds)
            
            # List secrets in this project
            request = secretmanager.projects().secrets().list(parent=f"projects/{project_id}")
            response = request.execute()
            project_secrets = response.get('secrets', [])
            
            if not project_secrets:
                print(f"[~] No secrets found in {project_id}")
                continue
            
            for secret in project_secrets:
                # Extract secret information
                secret_info = {
                    'name': secret.get('name', '').split('/')[-1],
                    'fullName': secret.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'createTime': secret.get('createTime'),
                    'labels': secret.get('labels', {}),
                    'replication': secret.get('replication', {}),
                    'secretId': secret.get('name', '').split('/')[-1],
                    'riskLevel': 'UNKNOWN'
                }
                
                # Try to get secret versions for additional analysis
                try:
                    versions_request = secretmanager.projects().secrets().versions().list(
                        parent=secret.get('name')
                    )
                    versions_response = versions_request.execute()
                    secret_info['versions'] = versions_response.get('versions', [])
                    secret_info['versionCount'] = len(versions_response.get('versions', []))
                except Exception:
                    secret_info['versions'] = []
                    secret_info['versionCount'] = 0
                
                # Assess security risk level
                secret_info = _assess_secret_risk(secret_info)
                
                secrets.append(secret_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if secret_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if secret_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                version_count = secret_info['versionCount']
                print(f"    {colorize('🔐', risk_color)} {secret_info['name']} ({version_count} versions) - {colorize(secret_info['riskLevel'] + ' RISK', risk_color)}")
            
            if project_secrets:
                high_risk = len([s for s in secrets if s.get('project') == project_id and s['riskLevel'] == 'HIGH'])
                medium_risk = len([s for s in secrets if s.get('project') == project_id and s['riskLevel'] == 'MEDIUM'])
                total_in_project = len([s for s in secrets if s.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} secrets in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk secrets")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk secrets")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Secret Manager access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Secret Manager API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Secret Manager in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Secret Manager in {project_id}: {e}")
    
    # Final summary - CONDITIONAL
    total_secrets = len(secrets)
    high_risk_secrets = len([s for s in secrets if s['riskLevel'] == 'HIGH'])
    medium_risk_secrets = len([s for s in secrets if s['riskLevel'] == 'MEDIUM'])
    
    if total_secrets > 0:  # Only show summary if secrets exist
        print(f"\n{colorize('[+] SECRET MANAGER ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('🔐 Total Secrets Discovered:', TerminalColors.BLUE)} {colorize(str(total_secrets), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Secrets:', TerminalColors.RED)} {colorize(str(high_risk_secrets), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ MEDIUM-Risk Secrets:', TerminalColors.YELLOW)} {colorize(str(medium_risk_secrets), TerminalColors.WHITE)}")
    
    return secrets

def _assess_secret_risk(secret_info):
    """Assess security risk level of a secret."""
    risk_factors = 0
    secret_name = secret_info['name'].lower()
    
    # High-value secret names (common patterns)
    high_value_patterns = ['password', 'key', 'token', 'api', 'secret', 'auth', 'cert', 'private']
    if any(pattern in secret_name for pattern in high_value_patterns):
        risk_factors += 2
    
    # Database-related secrets
    db_patterns = ['db', 'database', 'sql', 'mysql', 'postgres', 'mongo']
    if any(pattern in secret_name for pattern in db_patterns):
        risk_factors += 2
    
    # Many versions (frequent rotation or potential issues)
    version_count = secret_info.get('versionCount', 0)
    if version_count > 10:
        risk_factors += 1
    elif version_count > 5:
        risk_factors += 0.5
    
    # No labels (poor organization/management)
    if not secret_info.get('labels'):
        risk_factors += 1
    
    # Production-related labels
    labels = secret_info.get('labels', {})
    for key, value in labels.items():
        if 'prod' in key.lower() or 'prod' in value.lower():
            risk_factors += 1
            break
    
    # Assess overall risk
    if risk_factors >= 4:
        secret_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        secret_info['riskLevel'] = 'MEDIUM'
    else:
        secret_info['riskLevel'] = 'LOW'
    
    return secret_info

def analyze_secret_access_privileges(creds, secrets, service_accounts):
    """
    Analyze which service accounts can access which secrets.
    """
    access_analysis = []
    
    print(f"\n{colorize('[*] ANALYZING SECRET ACCESS PRIVILEGES...', TerminalColors.CYAN)}")
    
    for secret in secrets:
        secret_name = secret['name']
        project_id = secret['project']
        full_secret_name = secret['fullName']
        
        secret_access = {
            'secret': secret_name,
            'project': project_id,
            'canAccessSecret': [],
            'escalationRisk': 'LOW'
        }
        
        # Test secret access for service accounts in the same project
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            can_access = _test_secret_access(creds, full_secret_name, sa_email)
            
            if can_access:
                secret_access['canAccessSecret'].append({
                    'serviceAccount': sa_email,
                    'displayName': sa.get('displayName', sa_email)
                })
                print(f"    {colorize('🔓', TerminalColors.CYAN)} {sa.get('displayName', sa_email)}: Can access secret {colorize(secret_name, TerminalColors.WHITE)}")
        
        # Assess escalation risk
        if len(secret_access['canAccessSecret']) > 2:
            secret_access['escalationRisk'] = 'HIGH'
        elif len(secret_access['canAccessSecret']) > 0:
            secret_access['escalationRisk'] = 'MEDIUM'
        
        access_analysis.append(secret_access)
    
    # Summary
    high_risk_secrets = len([s for s in access_analysis if s['escalationRisk'] == 'HIGH'])
    medium_risk_secrets = len([s for s in access_analysis if s['escalationRisk'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] SECRET ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('🚨 HIGH Risk Secret Access:', TerminalColors.RED)} {colorize(str(high_risk_secrets), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM Risk Secret Access:', TerminalColors.YELLOW)} {colorize(str(medium_risk_secrets), TerminalColors.WHITE)}")
    
    return access_analysis

def _test_secret_access(creds, secret_name, service_account_email):
    """Test if a service account can access a specific secret."""
    try:
        # Use IAM API to test secret access permission
        iam = build("iam", "v1", credentials=creds)
        
        # Extract project from secret name
        project_id = secret_name.split('/')[1]
        
        # Test service account permissions for secret access
        test_request = iam.projects().serviceAccounts().testIamPermissions(
            resource=f"projects/{project_id}/serviceAccounts/{service_account_email}",
            body={'permissions': [
                'secretmanager.versions.access',
                'secretmanager.secrets.get'
            ]}
        )
        test_response = test_request.execute()
        
        granted_permissions = test_response.get('permissions', [])
        return len(granted_permissions) > 0
        
    except Exception:
        return False

def build_secret_access_edges(secrets, secret_access_analysis, current_user):
    """
    Build BloodHound edges for secret access relationships.
    """
    edges = []
    
    for secret in secrets:
        secret_name = secret['name']
        project_id = secret['project']
        secret_id = f"gcp-secret-{project_id}-{secret_name}"
        
        # Edge: Secret belongs to project
        edges.append({
            "start": {"value": secret_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "secret_enumeration",
                "secretName": secret_name,
                "riskLevel": secret['riskLevel'],
                "versionCount": secret['versionCount']
            }
        })
    
    # Edges for service account access to secrets
    for analysis in secret_access_analysis:
        secret_name = analysis['secret']
        project_id = analysis['project']
        secret_id = f"gcp-secret-{project_id}-{secret_name}"
        
        for access in analysis['canAccessSecret']:
            sa_email = access['serviceAccount']
            sa_id = sa_email.replace('@', '_').replace('.', '_')
            
            edges.append({
                "start": {"value": f"gcp-sa-{sa_id}"},
                "end": {"value": secret_id},
                "kind": "CanAccessSecret",
                "properties": {
                    "source": "secret_access_analysis",
                    "riskLevel": analysis['escalationRisk'],
                    "description": f"Service account can access secret {secret_name}",
                    "escalationMethod": "secret_access"
                }
            })
    
    return edges
