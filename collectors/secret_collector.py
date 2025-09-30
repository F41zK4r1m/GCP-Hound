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

def collect_paginated_secrets(secretmanager_client, project_id):
    """
    Helper function to collect all paginated secrets from a project.
    
    Args:
        secretmanager_client: Built Secret Manager API client
        project_id: GCP project ID to list secrets from
    
    Returns:
        Tuple of (all_secrets_list, page_count)
    """
    all_secrets = []
    request = secretmanager_client.projects().secrets().list(parent=f"projects/{project_id}")
    page_count = 0
    
    while request is not None:
        try:
            response = request.execute()
            secrets = response.get('secrets', [])
            all_secrets.extend(secrets)
            page_count += 1
            
            # Get next page request
            request = secretmanager_client.projects().secrets().list_next(request, response)
            
        except HttpError as e:
            # If we get SERVICE_DISABLED during pagination, break and handle gracefully
            if any(keyword in str(e) for keyword in ['SERVICE_DISABLED', 'API has not been used', 'not enabled']):
                print(f"[!] Secret Manager API not enabled for project {project_id}")
                all_secrets = []  # Clear any partial results
                break
            else:
                raise  # Re-raise other HTTP errors
        except Exception as e:
            print(f"[!] Error during secret pagination: {e}")
            break
    
    return all_secrets, page_count

def assess_secret_access_privileges(secret_info, iam_data):
    """
    Analyze which identities can access this secret and flag high-risk access patterns.
    This enriches secret data with access metadata for edge building.
    
    Args:
        secret_info: Secret information dictionary from enumeration
        iam_data: List of IAM policy dictionaries from all projects
        
    Returns:
        Updated secret_info dict with accessAnalysis metadata
    """
    secret_name = secret_info.get('name')
    project_id = secret_info.get('project')
    full_secret_name = secret_info.get('fullName')
    
    secret_access = {
        'canReadSecret': [],
        'canManageSecret': [],
        'hasAdminAccess': False,
        'riskLevel': 'LOW',
        'accessCount': 0,
        'projectLevelAccess': [],
        'specificSecretAccess': []
    }
    
    if not secret_name or not project_id:
        secret_info['accessAnalysis'] = secret_access
        return secret_info
    
    # Check IAM bindings for this project to find who can access this secret
    for iam_policy in iam_data:
        if iam_policy.get('projectId') != project_id:
            continue
            
        for binding in iam_policy.get('bindings', []):
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            for member in members:
                # Check for secret read permissions
                if role in [
                    'roles/secretmanager.secretAccessor',
                    'roles/secretmanager.viewer'
                ]:
                    access_info = {
                        'identity': member,
                        'role': role,
                        'accessType': 'read',
                        'scope': 'specific'
                    }
                    secret_access['canReadSecret'].append(access_info)
                    secret_access['specificSecretAccess'].append(access_info)
                    
                # Check for secret management permissions
                elif role in [
                    'roles/secretmanager.admin',
                    'roles/secretmanager.secretManager'
                ]:
                    access_info = {
                        'identity': member,
                        'role': role,
                        'accessType': 'manage',
                        'scope': 'project'
                    }
                    secret_access['canManageSecret'].append(access_info)
                    secret_access['canReadSecret'].append(access_info)  # Admin implies read
                    secret_access['hasAdminAccess'] = True
                    secret_access['projectLevelAccess'].append(access_info)
                
                # Check for broad administrative roles
                elif role in [
                    'roles/owner',
                    'roles/editor'
                ]:
                    access_info = {
                        'identity': member,
                        'role': role,
                        'accessType': 'manage',
                        'scope': 'project'
                    }
                    secret_access['canManageSecret'].append(access_info)
                    secret_access['canReadSecret'].append(access_info)
                    secret_access['hasAdminAccess'] = True
                    secret_access['projectLevelAccess'].append(access_info)
    
    # Calculate total access count and assess risk
    secret_access['accessCount'] = len(secret_access['canReadSecret'])
    
    # Enhanced risk assessment based on access patterns
    if secret_access['hasAdminAccess'] and secret_access['accessCount'] > 5:
        secret_access['riskLevel'] = 'CRITICAL'
    elif secret_access['hasAdminAccess'] or secret_access['accessCount'] > 3:
        secret_access['riskLevel'] = 'HIGH'
    elif secret_access['accessCount'] > 1:
        secret_access['riskLevel'] = 'MEDIUM'
    elif secret_access['accessCount'] == 0:
        secret_access['riskLevel'] = 'LOW'
    
    # Enrich the secret info with this analysis
    secret_info['accessAnalysis'] = secret_access
    return secret_info

def collect_secrets(creds, projects):
    """
    Enumerate all Secret Manager secrets across accessible projects with pagination support.
    Returns a list of secret dicts with enhanced security analysis.
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
            
            # Use pagination to get ALL secrets in this project
            project_secrets, page_count = collect_paginated_secrets(secretmanager, project_id)
            
            if not project_secrets:
                print(f"[~] No secrets found in {project_id}")
                continue
            
            for secret in project_secrets:
                # Extract secret information with enhanced metadata
                secret_info = {
                    'name': secret.get('name', '').split('/')[-1],
                    'fullName': secret.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'createTime': secret.get('createTime'),
                    'labels': secret.get('labels', {}),
                    'replication': secret.get('replication', {}),
                    'secretId': secret.get('name', '').split('/')[-1],
                    'riskLevel': 'UNKNOWN',
                    # Enhanced metadata
                    'annotations': secret.get('annotations', {}),
                    'expireTime': secret.get('expireTime'),
                    'ttl': secret.get('ttl')
                }
                
                # Try to get secret versions for additional analysis with pagination
                try:
                    versions_request = secretmanager.projects().secrets().versions().list(
                        parent=secret.get('name')
                    )
                    
                    # Add pagination for versions as well
                    all_versions = []
                    while versions_request is not None:
                        try:
                            versions_response = versions_request.execute()
                            page_versions = versions_response.get('versions', [])
                            all_versions.extend(page_versions)
                            
                            # Get next page of versions
                            versions_request = secretmanager.projects().secrets().versions().list_next(
                                versions_request, versions_response
                            )
                        except:
                            break
                    
                    secret_info['versions'] = all_versions
                    secret_info['versionCount'] = len(all_versions)
                    
                    # Enhanced version analysis
                    if all_versions:
                        latest_version = all_versions[0] if all_versions else None
                        secret_info['latestVersion'] = latest_version
                        secret_info['hasEnabledVersions'] = any(
                            v.get('state') == 'ENABLED' for v in all_versions
                        )
                    
                except Exception:
                    secret_info['versions'] = []
                    secret_info['versionCount'] = 0
                    secret_info['hasEnabledVersions'] = False
                
                # Assess security risk level with enhanced analysis
                secret_info = assess_secret_risk_enhanced(secret_info)
                
                secrets.append(secret_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if secret_info['riskLevel'] == 'CRITICAL' else \
                            TerminalColors.RED if secret_info['riskLevel'] == 'HIGH' else \
                            TerminalColors.YELLOW if secret_info['riskLevel'] == 'MEDIUM' else \
                            TerminalColors.GREEN
                version_count = secret_info['versionCount']
                has_enabled = "enabled" if secret_info.get('hasEnabledVersions') else "disabled"
                print(f"    {colorize('🔐', risk_color)} {secret_info['name']} ({version_count} versions, {has_enabled}) - {colorize(secret_info['riskLevel'] + ' RISK', risk_color)}")
            
            if project_secrets:
                high_risk = len([s for s in secrets if s.get('project') == project_id and s['riskLevel'] in ['HIGH', 'CRITICAL']])
                medium_risk = len([s for s in secrets if s.get('project') == project_id and s['riskLevel'] == 'MEDIUM'])
                total_in_project = len([s for s in secrets if s.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} secrets in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH+ risk secrets")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk secrets")
                
        except HttpError as e:
            error_code = e.resp.status if hasattr(e, 'resp') else 'unknown'
            if error_code == 403:
                print(f"[!] No Secret Manager access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Secret Manager API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Secret Manager in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Secret Manager in {project_id}: {e}")
    
    # Enhanced final summary
    total_secrets = len(secrets)
    critical_risk_secrets = len([s for s in secrets if s['riskLevel'] == 'CRITICAL'])
    high_risk_secrets = len([s for s in secrets if s['riskLevel'] == 'HIGH'])
    medium_risk_secrets = len([s for s in secrets if s['riskLevel'] == 'MEDIUM'])
    
    if total_secrets > 0:  # Only show summary if secrets exist
        print(f"\n{colorize('[+] SECRET MANAGER ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('🔐 Total Secrets Discovered:', TerminalColors.BLUE)} {colorize(str(total_secrets), TerminalColors.WHITE)}")
        print(f"    {colorize('💀 CRITICAL-Risk Secrets:', TerminalColors.RED)} {colorize(str(critical_risk_secrets), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Secrets:', TerminalColors.RED)} {colorize(str(high_risk_secrets), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ MEDIUM-Risk Secrets:', TerminalColors.YELLOW)} {colorize(str(medium_risk_secrets), TerminalColors.WHITE)}")
    
    return secrets

def assess_secret_risk_enhanced(secret_info):
    """
    Enhanced security risk assessment for secrets with comprehensive analysis.
    
    Args:
        secret_info: Secret information dictionary
        
    Returns:
        Updated secret_info with riskLevel set
    """
    risk_factors = 0
    secret_name = secret_info['name'].lower()
    
    # High-value secret names (enhanced patterns)
    high_value_patterns = [
        'password', 'key', 'token', 'api', 'secret', 'auth', 'cert', 'private',
        'credential', 'pass', 'pwd', 'access', 'session'
    ]
    if any(pattern in secret_name for pattern in high_value_patterns):
        risk_factors += 2
    
    # Critical system patterns
    critical_patterns = ['root', 'admin', 'master', 'super', 'service']
    if any(pattern in secret_name for pattern in critical_patterns):
        risk_factors += 3
    
    # Database-related secrets (enhanced)
    db_patterns = [
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
        'cassandra', 'oracle', 'mssql', 'connection', 'dsn'
    ]
    if any(pattern in secret_name for pattern in db_patterns):
        risk_factors += 2
    
    # Cloud service patterns
    cloud_patterns = ['aws', 'azure', 'gcp', 'oauth', 'jwt', 'bearer', 'saml']
    if any(pattern in secret_name for pattern in cloud_patterns):
        risk_factors += 2
    
    # Version analysis
    version_count = secret_info.get('versionCount', 0)
    if version_count > 50:
        risk_factors += 2  # Too many versions might indicate issues
    elif version_count > 20:
        risk_factors += 1
    elif version_count == 0:
        risk_factors += 1  # No versions is suspicious
    
    # Check if secret has enabled versions
    if not secret_info.get('hasEnabledVersions', True):
        risk_factors += 1  # All versions disabled might indicate issues
    
    # Label analysis
    labels = secret_info.get('labels', {})
    if not labels:
        risk_factors += 1  # No labels = poor management
    else:
        # Production/critical environment labels
        for key, value in labels.items():
            key_lower = key.lower()
            value_lower = value.lower()
            if any(env in key_lower or env in value_lower for env in ['prod', 'production', 'critical', 'live']):
                risk_factors += 2
                break
    
    # Expiration analysis
    expire_time = secret_info.get('expireTime')
    if expire_time:
        # Secret has expiration (good practice)
        risk_factors -= 0.5
    else:
        # No expiration set
        risk_factors += 1
    
    # TTL analysis
    ttl = secret_info.get('ttl')
    if ttl:
        risk_factors -= 0.5  # TTL is good practice
    
    # Enhanced risk assessment with CRITICAL level
    if risk_factors >= 6:
        secret_info['riskLevel'] = 'CRITICAL'
    elif risk_factors >= 4:
        secret_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        secret_info['riskLevel'] = 'MEDIUM'
    else:
        secret_info['riskLevel'] = 'LOW'
    
    return secret_info

# Keep your existing _assess_secret_risk for backward compatibility
def _assess_secret_risk(secret_info):
    """Legacy risk assessment function - kept for backward compatibility"""
    return assess_secret_risk_enhanced(secret_info)

def collect_secrets_with_access_analysis(creds, projects, iam_data):
    """
    Enhanced wrapper that collects secrets and enriches them with access analysis.
    
    Args:
        creds: GCP credentials
        projects: List of project dictionaries
        iam_data: List of IAM policy dictionaries for access analysis
        
    Returns:
        List of enriched secret dictionaries with accessAnalysis metadata
    """
    print(f"\n{colorize('[*] COLLECTING SECRETS WITH ACCESS ANALYSIS...', TerminalColors.CYAN)}")
    
    # First collect all secrets
    secrets = collect_secrets(creds, projects)
    
    if not secrets:
        return secrets
    
    print(f"\n{colorize('[*] ANALYZING SECRET ACCESS PATTERNS...', TerminalColors.CYAN)}")
    
    # Enrich each secret with access analysis
    enriched_secrets = []
    access_summary = {
        'secrets_with_access': 0,
        'secrets_with_admin_access': 0,
        'high_access_secrets': 0,
        'total_access_relationships': 0
    }
    
    for secret in secrets:
        enriched_secret = assess_secret_access_privileges(secret, iam_data)
        enriched_secrets.append(enriched_secret)
        
        # Update summary statistics
        access_analysis = enriched_secret.get('accessAnalysis', {})
        access_count = access_analysis.get('accessCount', 0)
        
        if access_count > 0:
            access_summary['secrets_with_access'] += 1
            access_summary['total_access_relationships'] += access_count
            
        if access_analysis.get('hasAdminAccess'):
            access_summary['secrets_with_admin_access'] += 1
            
        if access_count > 3:
            access_summary['high_access_secrets'] += 1
    
    # Print access analysis summary
    print(f"\n{colorize('[+] SECRET ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('🔐 Secrets with Access:', TerminalColors.BLUE)} {colorize(str(access_summary['secrets_with_access']), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 Secrets with Admin Access:', TerminalColors.RED)} {colorize(str(access_summary['secrets_with_admin_access']), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ High Access Secrets (>3 identities):', TerminalColors.YELLOW)} {colorize(str(access_summary['high_access_secrets']), TerminalColors.WHITE)}")
    print(f"    {colorize('🔗 Total Access Relationships:', TerminalColors.BLUE)} {colorize(str(access_summary['total_access_relationships']), TerminalColors.WHITE)}")
    
    return enriched_secrets

def analyze_secret_access_privileges(creds, secrets, service_accounts):
    """
    Analyze which service accounts can access which secrets (legacy function - enhanced).
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
            can_access = test_secret_access_enhanced(creds, full_secret_name, sa_email)
            
            if can_access:
                secret_access['canAccessSecret'].append({
                    'serviceAccount': sa_email,
                    'displayName': sa.get('displayName', sa_email)
                })
                print(f"    {colorize('🔓', TerminalColors.CYAN)} {sa.get('displayName', sa_email)}: Can access secret {colorize(secret_name, TerminalColors.WHITE)}")
        
        # Enhanced escalation risk assessment
        access_count = len(secret_access['canAccessSecret'])
        if access_count > 3:
            secret_access['escalationRisk'] = 'HIGH'
        elif access_count > 1:
            secret_access['escalationRisk'] = 'MEDIUM'
        elif access_count > 0:
            secret_access['escalationRisk'] = 'LOW'
        
        access_analysis.append(secret_access)
    
    # Enhanced summary
    high_risk_secrets = len([s for s in access_analysis if s['escalationRisk'] == 'HIGH'])
    medium_risk_secrets = len([s for s in access_analysis if s['escalationRisk'] == 'MEDIUM'])
    total_access_relationships = sum(len(s['canAccessSecret']) for s in access_analysis)
    
    print(f"\n{colorize('[+] SECRET ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('🚨 HIGH Risk Secret Access:', TerminalColors.RED)} {colorize(str(high_risk_secrets), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM Risk Secret Access:', TerminalColors.YELLOW)} {colorize(str(medium_risk_secrets), TerminalColors.WHITE)}")
    print(f"    {colorize('🔗 Total Access Relationships:', TerminalColors.BLUE)} {colorize(str(total_access_relationships), TerminalColors.WHITE)}")
    
    return access_analysis

def test_secret_access_enhanced(creds, secret_name, service_account_email):
    """Enhanced test for secret access permissions with better error handling"""
    try:
        iam = build("iam", "v1", credentials=creds)
        
        # Extract project from secret name
        project_id = secret_name.split('/')[1]
        
        # Enhanced permission test
        test_request = iam.projects().serviceAccounts().testIamPermissions(
            resource=f"projects/{project_id}/serviceAccounts/{service_account_email}",
            body={'permissions': [
                'secretmanager.versions.access',
                'secretmanager.secrets.get',
                'secretmanager.versions.list'  # Additional permission
            ]}
        )
        test_response = test_request.execute()
        
        granted_permissions = test_response.get('permissions', [])
        # Need at least one secret access permission
        return len(granted_permissions) > 0
        
    except Exception:
        return False

# Keep your existing _test_secret_access for backward compatibility
def _test_secret_access(creds, secret_name, service_account_email):
    """Legacy secret access test function - kept for backward compatibility"""
    return test_secret_access_enhanced(creds, secret_name, service_account_email)

def build_secret_access_edges(secrets, secret_access_analysis, current_user):
    """
    Build enhanced BloodHound edges for secret access relationships.
    """
    edges = []
    
    for secret in secrets:
        secret_name = secret['name']
        project_id = secret['project']
        secret_id = f"gcp-secret-{project_id}-{secret_name}"
        
        # Enhanced edge: Secret belongs to project
        edges.append({
            "start": {"value": secret_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "secret_enumeration",
                "secretName": secret_name,
                "riskLevel": secret['riskLevel'],
                "versionCount": secret['versionCount'],
                "hasEnabledVersions": secret.get('hasEnabledVersions', False),
                "hasExpiration": bool(secret.get('expireTime')),
                "hasTTL": bool(secret.get('ttl'))
            }
        })
    
    # Enhanced edges for service account access to secrets
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
                "kind": "CanReadSecrets",  # Updated to match hybrid approach
                "properties": {
                    "source": "secret_access_analysis",
                    "riskLevel": analysis['escalationRisk'],
                    "description": f"Service account can access secret {secret_name}",
                    "escalationMethod": "secret_access",
                    "scope": "secret"
                }
            })
    
    return edges
