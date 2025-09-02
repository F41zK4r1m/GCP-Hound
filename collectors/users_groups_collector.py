from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from collections import defaultdict

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

def collect_users_and_groups(creds):
    """
    Enumerate all users and groups in the Google Workspace organization.
    Returns comprehensive user/group data with privilege analysis.
    """
    users = []
    groups = []
    group_memberships = []
    
    print(f"\n{colorize('[*] ENUMERATING GOOGLE WORKSPACE USERS AND GROUPS...', TerminalColors.CYAN)}")
    
    try:
        # Build Admin SDK Directory API client
        admin_service = build('admin', 'directory_v1', credentials=creds)
        
        # Enumerate all users
        print(f"    {colorize('👥', TerminalColors.BLUE)} Enumerating organization users...")
        users = _collect_all_users(admin_service)
        
        # Enumerate all groups
        print(f"    {colorize('👥', TerminalColors.BLUE)} Enumerating organization groups...")
        groups = _collect_all_groups(admin_service)
        
        # Map group memberships
        print(f"    {colorize('🔗', TerminalColors.BLUE)} Mapping group memberships...")
        group_memberships = _collect_group_memberships(admin_service, groups)
        
    except HttpError as e:
        error_code = e.resp.status
        if error_code == 403:
            print(f"[!] No Admin SDK Directory API access - requires domain administrator privileges")
        elif error_code == 404:
            print(f"[!] Admin SDK API not enabled or no Google Workspace organization")
        else:
            print(f"[!] HTTP {error_code} error accessing Admin SDK: {e}")
        return [], [], []
    except Exception as e:
        print(f"[!] Unexpected error accessing Admin SDK: {e}")
        return [], [], []
    
    # Analyze and summarize findings - CONDITIONAL
    _analyze_users_groups_summary(users, groups, group_memberships)
    
    return users, groups, group_memberships

def _collect_all_users(admin_service):
    """Collect all users in the organization."""
    users = []
    
    try:
        request = admin_service.users().list(
            customer='my_customer',
            maxResults=500,
            orderBy='email'
        )
        
        while request is not None:
            response = request.execute()
            batch_users = response.get('users', [])
            
            for user in batch_users:
                # Enrich user data with security analysis
                user_info = {
                    'id': user.get('id'),
                    'primaryEmail': user.get('primaryEmail'),
                    'name': user.get('name', {}),
                    'fullName': user.get('name', {}).get('fullName', 'Unknown'),
                    'givenName': user.get('name', {}).get('givenName', ''),
                    'familyName': user.get('name', {}).get('familyName', ''),
                    'isAdmin': user.get('isAdmin', False),
                    'isDelegatedAdmin': user.get('isDelegatedAdmin', False),
                    'isSuperAdmin': user.get('isSuperAdmin', False),
                    'suspended': user.get('suspended', False),
                    'archived': user.get('archived', False),
                    'orgUnitPath': user.get('orgUnitPath', '/'),
                    'lastLoginTime': user.get('lastLoginTime'),
                    'creationTime': user.get('creationTime'),
                    'agreedToTerms': user.get('agreedToTerms', False),
                    'ipWhitelisted': user.get('ipWhitelisted', False),
                    'emails': user.get('emails', []),
                    'aliases': user.get('aliases', []),
                    'nonEditableAliases': user.get('nonEditableAliases', []),
                    'customerId': user.get('customerId'),
                    'isMailboxSetup': user.get('isMailboxSetup', False),
                    'includeInGlobalAddressList': user.get('includeInGlobalAddressList', True),
                    'riskLevel': 'UNKNOWN'
                }
                
                # Assess user security risk
                user_info = _assess_user_risk(user_info)
                users.append(user_info)
                
                # Print user discovery with risk assessment
                risk_color = TerminalColors.RED if user_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if user_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                admin_status = _get_admin_status_display(user_info)
                print(f"        {colorize('👤', risk_color)} {user_info['primaryEmail']} {admin_status} - {colorize(user_info['riskLevel'] + ' RISK', risk_color)}")
            
            # Handle pagination
            request = admin_service.users().list_next(
                previous_request=request, previous_response=response)
            
    except Exception as e:
        print(f"    {colorize('!', TerminalColors.YELLOW)} Error collecting users: {e}")
    
    return users

def _collect_all_groups(admin_service):
    """Collect all groups in the organization."""
    groups = []
    
    try:
        request = admin_service.groups().list(
            customer='my_customer',
            maxResults=200
        )
        
        while request is not None:
            response = request.execute()
            batch_groups = response.get('groups', [])
            
            for group in batch_groups:
                # Enrich group data
                group_info = {
                    'id': group.get('id'),
                    'email': group.get('email'),
                    'name': group.get('name'),
                    'description': group.get('description', ''),
                    'directMembersCount': group.get('directMembersCount', 0),
                    'adminCreated': group.get('adminCreated', False),
                    'aliases': group.get('aliases', []),
                    'nonEditableAliases': group.get('nonEditableAliases', []),
                    'members': [],  # Will be populated later
                    'riskLevel': 'UNKNOWN'
                }
                
                groups.append(group_info)
                member_count = group_info['directMembersCount']
                print(f"        {colorize('👥', TerminalColors.CYAN)} {group_info['email']} ({member_count} members)")
            
            # Handle pagination
            request = admin_service.groups().list_next(
                previous_request=request, previous_response=response)
            
    except Exception as e:
        print(f"    {colorize('!', TerminalColors.YELLOW)} Error collecting groups: {e}")
    
    return groups

def _collect_group_memberships(admin_service, groups):
    """Collect membership information for all groups."""
    group_memberships = []
    
    for group in groups:
        group_email = group['email']
        
        try:
            request = admin_service.members().list(
                groupKey=group_email,
                maxResults=200
            )
            
            group_members = []
            while request is not None:
                response = request.execute()
                members = response.get('members', [])
                
                for member in members:
                    member_info = {
                        'groupEmail': group_email,
                        'memberEmail': member.get('email'),
                        'memberId': member.get('id'),
                        'role': member.get('role', 'MEMBER'),  # OWNER, MANAGER, MEMBER
                        'type': member.get('type', 'USER'),   # USER, GROUP, CUSTOMER
                        'status': member.get('status', 'ACTIVE')
                    }
                    
                    group_members.append(member_info)
                    group_memberships.append(member_info)
                
                # Handle pagination
                request = admin_service.members().list_next(
                    previous_request=request, previous_response=response)
            
            # Update group with members
            group['members'] = group_members
            
            # Assess group risk based on membership
            group = _assess_group_risk(group)
            
        except Exception as e:
            print(f"    {colorize('!', TerminalColors.YELLOW)} Error collecting members for {group_email}: {e}")
    
    return group_memberships

def _assess_user_risk(user_info):
    """Assess security risk level of a user."""
    risk_factors = 0
    
    # High-privilege users
    if user_info['isSuperAdmin']:
        risk_factors += 3
    elif user_info['isAdmin']:
        risk_factors += 2
    elif user_info['isDelegatedAdmin']:
        risk_factors += 1
    
    # Suspended or archived accounts (potential security issues)
    if user_info['suspended'] or user_info['archived']:
        risk_factors += 1
    
    # External domain detection (if email domain doesn't match organization)
    email = user_info['primaryEmail']
    if '@gmail.com' in email or '@googlemail.com' in email:
        risk_factors += 2  # Personal Gmail accounts in organization
    
    # No recent login (stale accounts)
    if not user_info['lastLoginTime']:
        risk_factors += 1
    
    # Not agreed to terms
    if not user_info['agreedToTerms']:
        risk_factors += 1
    
    # Multiple aliases (potential for confusion/impersonation)
    if len(user_info['aliases']) > 3:
        risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 4:
        user_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        user_info['riskLevel'] = 'MEDIUM'
    else:
        user_info['riskLevel'] = 'LOW'
    
    return user_info

def _assess_group_risk(group_info):
    """Assess security risk level of a group."""
    risk_factors = 0
    
    # Large groups (privilege inheritance risk)
    member_count = len(group_info['members'])
    if member_count > 100:
        risk_factors += 2
    elif member_count > 20:
        risk_factors += 1
    
    # Groups with owners/managers (elevated privileges)
    privileged_members = [m for m in group_info['members'] 
                         if m['role'] in ['OWNER', 'MANAGER']]
    if len(privileged_members) > 5:
        risk_factors += 1
    
    # Groups with nested group memberships (complex inheritance)
    nested_groups = [m for m in group_info['members'] if m['type'] == 'GROUP']
    if len(nested_groups) > 0:
        risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 3:
        group_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 1:
        group_info['riskLevel'] = 'MEDIUM'
    else:
        group_info['riskLevel'] = 'LOW'
    
    return group_info

def _get_admin_status_display(user_info):
    """Get display string for user admin status."""
    if user_info['isSuperAdmin']:
        return f"({colorize('SUPER ADMIN', TerminalColors.RED + TerminalColors.BOLD)})"
    elif user_info['isAdmin']:
        return f"({colorize('ADMIN', TerminalColors.RED)})"
    elif user_info['isDelegatedAdmin']:
        return f"({colorize('DELEGATED ADMIN', TerminalColors.YELLOW)})"
    elif user_info['suspended']:
        return f"({colorize('SUSPENDED', TerminalColors.RED)})"
    elif user_info['archived']:
        return f"({colorize('ARCHIVED', TerminalColors.YELLOW)})"
    else:
        return ""

def _analyze_users_groups_summary(users, groups, group_memberships):
    """Analyze and print comprehensive summary only if users/groups exist."""
    total_users = len(users)
    total_groups = len(groups)
    
    if total_users > 0 or total_groups > 0:  # Only show if data exists
        # User analysis
        super_admins = len([u for u in users if u['isSuperAdmin']])
        admins = len([u for u in users if u['isAdmin']])
        delegated_admins = len([u for u in users if u['isDelegatedAdmin']])
        suspended_users = len([u for u in users if u['suspended']])
        external_users = len([u for u in users if '@gmail.com' in u['primaryEmail'] or '@googlemail.com' in u['primaryEmail']])
        high_risk_users = len([u for u in users if u['riskLevel'] == 'HIGH'])
        
        # Group analysis
        large_groups = len([g for g in groups if len(g['members']) > 20])
        high_risk_groups = len([g for g in groups if g['riskLevel'] == 'HIGH'])
        total_memberships = len(group_memberships)
        
        print(f"\n{colorize('[+] USERS AND GROUPS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('👥 Total Users Discovered:', TerminalColors.BLUE)} {colorize(str(total_users), TerminalColors.WHITE)}")
        print(f"    {colorize('👑 Super Administrators:', TerminalColors.RED)} {colorize(str(super_admins), TerminalColors.WHITE)}")
        print(f"    {colorize('🔑 Administrators:', TerminalColors.YELLOW)} {colorize(str(admins), TerminalColors.WHITE)}")
        print(f"    {colorize('🔐 Delegated Administrators:', TerminalColors.YELLOW)} {colorize(str(delegated_admins), TerminalColors.WHITE)}")
        print(f"    {colorize('⛔ Suspended Users:', TerminalColors.RED)} {colorize(str(suspended_users), TerminalColors.WHITE)}")
        print(f"    {colorize('🌐 External Users:', TerminalColors.RED)} {colorize(str(external_users), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Users:', TerminalColors.RED)} {colorize(str(high_risk_users), TerminalColors.WHITE)}")
        print(f"    {colorize('👥 Total Groups:', TerminalColors.BLUE)} {colorize(str(total_groups), TerminalColors.WHITE)}")
        print(f"    {colorize('📊 Large Groups (>20 members):', TerminalColors.YELLOW)} {colorize(str(large_groups), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Groups:', TerminalColors.RED)} {colorize(str(high_risk_groups), TerminalColors.WHITE)}")
        print(f"    {colorize('🔗 Total Group Memberships:', TerminalColors.BLUE)} {colorize(str(total_memberships), TerminalColors.WHITE)}")

def analyze_users_groups_privilege_escalation(users, groups, group_memberships, service_accounts):
    """
    Analyze privilege escalation opportunities through user/group relationships.
    """
    escalation_analysis = {
        'adminUsers': [],
        'privilegedGroups': [],
        'externalUsers': [],
        'suspiciousMemberships': [],
        'escalationRisk': 'LOW'
    }
    
    print(f"\n{colorize('[*] ANALYZING USER/GROUP PRIVILEGE ESCALATION PATHS...', TerminalColors.CYAN)}")
    
    # Analyze high-privilege users
    for user in users:
        if user['isSuperAdmin'] or user['isAdmin'] or user['isDelegatedAdmin']:
            escalation_analysis['adminUsers'].append({
                'email': user['primaryEmail'],
                'adminType': 'Super Admin' if user['isSuperAdmin'] else 'Admin' if user['isAdmin'] else 'Delegated Admin',
                'riskLevel': user['riskLevel']
            })
            print(f"    {colorize('👑 HIGH PRIVILEGE', TerminalColors.RED + TerminalColors.BOLD)} {user['primaryEmail']}: {user.get('adminType', 'Admin')} user")
    
    # Analyze privileged groups
    for group in groups:
        if group['riskLevel'] == 'HIGH' or len(group['members']) > 50:
            escalation_analysis['privilegedGroups'].append({
                'email': group['email'],
                'memberCount': len(group['members']),
                'riskLevel': group['riskLevel']
            })
            print(f"    {colorize('👥 LARGE GROUP', TerminalColors.YELLOW)} {group['email']}: {len(group['members'])} members - potential privilege inheritance")
    
    # Analyze external users
    for user in users:
        if '@gmail.com' in user['primaryEmail'] or '@googlemail.com' in user['primaryEmail']:
            escalation_analysis['externalUsers'].append({
                'email': user['primaryEmail'],
                'isAdmin': user['isAdmin'] or user['isSuperAdmin']
            })
            print(f"    {colorize('🌐 EXTERNAL USER', TerminalColors.RED)} {user['primaryEmail']}: External domain in organization")
    
    # Cross-reference with service accounts
    user_emails = [u['primaryEmail'] for u in users]
    sa_emails = [sa.get('email', '') for sa in service_accounts]
    
    # Look for users who might have service account access
    for sa in service_accounts:
        sa_email = sa.get('email', '')
        sa_domain = sa_email.split('@')[1] if '@' in sa_email else ''
        
        # Check if any users are in the same domain as service accounts
        matching_users = [u for u in users if sa_domain in u['primaryEmail']]
        if len(matching_users) > 0:
            print(f"    {colorize('🔗 POTENTIAL SA ACCESS', TerminalColors.CYAN)} Users in domain {sa_domain} may access service account {sa.get('displayName', sa_email)}")
    
    # Assess overall escalation risk
    risk_factors = len(escalation_analysis['adminUsers']) + len(escalation_analysis['externalUsers']) + len(escalation_analysis['privilegedGroups'])
    if risk_factors >= 5:
        escalation_analysis['escalationRisk'] = 'HIGH'
    elif risk_factors >= 2:
        escalation_analysis['escalationRisk'] = 'MEDIUM'
    
    # Summary
    print(f"\n{colorize('[+] USER/GROUP PRIVILEGE ESCALATION SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('👑 Administrative Users:', TerminalColors.RED)} {colorize(str(len(escalation_analysis['adminUsers'])), TerminalColors.WHITE)}")
    print(f"    {colorize('👥 High-Risk Groups:', TerminalColors.YELLOW)} {colorize(str(len(escalation_analysis['privilegedGroups'])), TerminalColors.WHITE)}")
    print(f"    {colorize('🌐 External Users:', TerminalColors.RED)} {colorize(str(len(escalation_analysis['externalUsers'])), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ Overall Escalation Risk:', TerminalColors.YELLOW)} {colorize(escalation_analysis['escalationRisk'], TerminalColors.WHITE)}")
    
    return escalation_analysis

def build_users_groups_edges(users, groups, group_memberships, escalation_analysis, current_user):
    """
    Build BloodHound edges for user/group relationships and privilege escalation paths.
    """
    edges = []
    
    # Edges: Users belong to groups
    for membership in group_memberships:
        user_email = membership['memberEmail']
        group_email = membership['groupEmail']
        role = membership['role']
        
        user_id = user_email.replace('@', '_').replace('.', '_')
        group_id = group_email.replace('@', '_').replace('.', '_')
        
        edges.append({
            "start": {"value": f"gcp-user-{user_id}"},
            "end": {"value": f"gcp-group-{group_id}"},
            "kind": "MemberOf",
            "properties": {
                "source": "users_groups_enumeration",
                "role": role,
                "memberType": membership['type'],
                "status": membership['status'],
                "description": f"User {user_email} is {role} of group {group_email}"
            }
        })
    
    # Edges: Administrative privilege escalation
    for admin_user in escalation_analysis['adminUsers']:
        user_email = admin_user['email']
        user_id = user_email.replace('@', '_').replace('.', '_')
        
        edges.append({
            "start": {"value": f"user-{current_user}"},
            "end": {"value": f"gcp-user-{user_id}"},
            "kind": "CanEscalateToAdmin",
            "properties": {
                "source": "users_groups_privilege_analysis",
                "adminType": admin_user['adminType'],
                "riskLevel": admin_user['riskLevel'],
                "description": f"Can potentially escalate to {admin_user['adminType']} user {user_email}",
                "escalationMethod": "admin_user_compromise"
            }
        })
    
    # Edges: Group-based privilege inheritance
    for priv_group in escalation_analysis['privilegedGroups']:
        group_email = priv_group['email']
        group_id = group_email.replace('@', '_').replace('.', '_')
        
        edges.append({
            "start": {"value": f"user-{current_user}"},
            "end": {"value": f"gcp-group-{group_id}"},
            "kind": "CanEscalateViaGroup",
            "properties": {
                "source": "users_groups_privilege_analysis",
                "memberCount": priv_group['memberCount'],
                "riskLevel": priv_group['riskLevel'],
                "description": f"Can escalate privileges through large group {group_email}",
                "escalationMethod": "group_privilege_inheritance"
            }
        })
    
    return edges
