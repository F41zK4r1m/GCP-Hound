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

def analyze_service_account_key_access(creds, service_accounts, args=None):
    """
    Analyze service account key access capabilities - critical for privilege escalation analysis.
    Tests: list keys, create keys, and impersonation permissions for each service account.
    """
    key_access_analysis = []
    
    if args and args.verbose:
        print(f"\n{colorize('[*] ANALYZING SERVICE ACCOUNT KEY ACCESS FOR PRIVILEGE ESCALATION...', TerminalColors.CYAN)}")
    
    for sa in service_accounts:
        sa_email = sa.get('email')
        project_id = sa.get('project')
        sa_name = sa.get('displayName', sa_email)
        
        if not sa_email or not project_id:
            continue
            
        analysis_result = {
            'serviceAccount': sa_email,
            'project': project_id,
            'displayName': sa_name,
            'canListKeys': False,
            'canCreateKeys': False,
            'canImpersonate': False,
            'existingKeys': [],
            'impersonationRoles': [],
            'riskLevel': 'LOW'
        }
        
        try:
            iam = build("iam", "v1", credentials=creds)
            
            # Test 1: Can we list existing keys for this service account?
            try:
                keys_request = iam.projects().serviceAccounts().keys().list(
                    name=f"projects/{project_id}/serviceAccounts/{sa_email}"
                )
                keys_response = keys_request.execute()
                existing_keys = keys_response.get('keys', [])
                
                analysis_result['canListKeys'] = True
                analysis_result['existingKeys'] = existing_keys
                if args and args.verbose:
                    print(f"    {colorize('✓', TerminalColors.GREEN)} {sa_name}: Can list {colorize(str(len(existing_keys)), TerminalColors.WHITE)} existing keys")
                
            except HttpError as e:
                if args and args.debug:
                    print(f"[DEBUG] Key listing failed for {sa_name}: {e}")
                elif "Unable to find the server" in str(e):
                    if args and args.verbose:
                        print(f"    ! {sa_name}: Network error during key listing (use -d for details)")
                elif e.resp.status == 403:
                    if args and args.verbose:
                        print(f"    {colorize('✗', TerminalColors.RED)} {sa_name}: Cannot list keys (403 Forbidden)")
                else:
                    if args and args.verbose:
                        print(f"    {colorize('!', TerminalColors.YELLOW)} {sa_name}: Error listing keys")
            
            # Test 2: Check if we can create new keys (test permissions without actually creating)
            try:
                # Use testIamPermissions to check create key capability
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={
                        'permissions': [
                            'iam.serviceAccountKeys.create',
                            'iam.serviceAccounts.actAs',
                            'iam.serviceAccounts.getAccessToken'
                        ]
                    }
                )
                test_response = test_request.execute()
                granted_permissions = test_response.get('permissions', [])
                
                if 'iam.serviceAccountKeys.create' in granted_permissions:
                    analysis_result['canCreateKeys'] = True
                    analysis_result['riskLevel'] = 'CRITICAL'
                    if args and args.verbose:
                        print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} {sa_name}: Can create keys - {colorize('PRIVILEGE ESCALATION POSSIBLE', TerminalColors.RED)}")
                
                if 'iam.serviceAccounts.actAs' in granted_permissions:
                    analysis_result['canImpersonate'] = True
                    analysis_result['impersonationRoles'].append('serviceAccountUser')
                    if args and args.verbose:
                        print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} {sa_name}: Can impersonate service account")
                
                if 'iam.serviceAccounts.getAccessToken' in granted_permissions:
                    analysis_result['impersonationRoles'].append('serviceAccountTokenCreator')
                    if args and args.verbose:
                        print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} {sa_name}: Can generate access tokens")
                
            except HttpError as e:
                if args and args.debug:
                    print(f"[DEBUG] Key creation test failed for {sa_name}: {e}")
                elif "Unable to find the server" in str(e):
                    if args and args.verbose:
                        print(f"    ! {sa_name}: Network error during key creation test (use -d for details)")
                elif e.resp.status != 403:  # 403 is expected for no permissions
                    if args and args.verbose:
                        print(f"    {colorize('!', TerminalColors.YELLOW)} {sa_name}: Error testing permissions")
            
            # Risk assessment
            if analysis_result['canCreateKeys']:
                analysis_result['riskLevel'] = 'CRITICAL'
            elif analysis_result['canImpersonate']:
                analysis_result['riskLevel'] = 'HIGH'
            elif analysis_result['canListKeys']:
                analysis_result['riskLevel'] = 'MEDIUM'
                
        except Exception as e:
            if args and args.debug:
                print(f"[DEBUG] Unexpected error analyzing {sa_name}: {e}")
            elif "Unable to find the server" in str(e):
                if args and args.verbose:
                    print(f"    ! {sa_name}: Network error (use -d for details)")
            else:
                if args and args.verbose:
                    print(f"    {colorize('!', TerminalColors.YELLOW)} {sa_name}: Analysis error (use -d for details)")
        
        key_access_analysis.append(analysis_result)
    
    # Summary of privilege escalation opportunities
    critical_escalations = [r for r in key_access_analysis if r['canCreateKeys']]
    impersonation_paths = [r for r in key_access_analysis if r['canImpersonate']]
    key_access_paths = [r for r in key_access_analysis if r['canListKeys']]
    
    if args and args.verbose:
        print(f"\n{colorize('[+] SERVICE ACCOUNT KEY ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('🚨 CRITICAL Escalations (can create keys):', TerminalColors.RED)} {colorize(str(len(critical_escalations)), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ Impersonation Paths:', TerminalColors.YELLOW)} {colorize(str(len(impersonation_paths)), TerminalColors.WHITE)}")
        print(f"    {colorize('📋 Key Listing Access:', TerminalColors.BLUE)} {colorize(str(len(key_access_paths)), TerminalColors.WHITE)}")
        
        if critical_escalations:
            print(f"    \n    {colorize('⚡ IMMEDIATE PRIVILEGE ESCALATION OPPORTUNITIES:', TerminalColors.RED + TerminalColors.BOLD)}")
            for crit in critical_escalations:
                print(f"       {colorize('•', TerminalColors.RED)} {colorize(crit['displayName'], TerminalColors.WHITE)} ({colorize(crit['serviceAccount'], TerminalColors.CYAN)})")
    
    return key_access_analysis

def build_key_access_edges(service_accounts, key_analysis, current_user):
    """
    Build BloodHound edges for service account key access relationships.
    """
    edges = []
    
    for analysis in key_analysis:
        sa_email = analysis['serviceAccount']
        
        # Edge: Current user can list keys for service account
        if analysis['canListKeys']:
            edges.append({
                "kind": "CanListKeys",
                "start": {"value": current_user, "match_by": "id"},
                "end": {"value": sa_email, "match_by": "id"},
                "properties": {
                    "source": "key_access_analysis",
                    "riskLevel": "MEDIUM",
                    "description": "Can enumerate existing service account keys",
                    "keyCount": len(analysis['existingKeys'])
                }
            })
        
        # Edge: Current user can create keys for service account (CRITICAL)
        if analysis['canCreateKeys']:
            edges.append({
                "kind": "CanCreateKeys",
                "start": {"value": current_user, "match_by": "id"},
                "end": {"value": sa_email, "match_by": "id"},
                "properties": {
                    "source": "key_access_analysis",
                    "riskLevel": "CRITICAL",
                    "description": "Can create service account keys - direct privilege escalation",
                    "escalationMethod": "service_account_key_creation"
                }
            })
        
        # Edge: Current user can impersonate service account
        if analysis['canImpersonate']:
            edges.append({
                "kind": "CanImpersonate",
                "start": {"value": current_user, "match_by": "id"},
                "end": {"value": sa_email, "match_by": "id"},
                "properties": {
                    "source": "key_access_analysis", 
                    "riskLevel": "HIGH",
                    "description": f"Can impersonate via: {', '.join(analysis['impersonationRoles'])}",
                    "methods": analysis['impersonationRoles']
                }
            })
    
    return edges
