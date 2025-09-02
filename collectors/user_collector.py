from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def collect_users(creds, projects):
    """
    Enumerate users and groups from Google Workspace.
    Requires Google Workspace Admin SDK access.
    """
    users = []
    groups = []
    group_memberships = []
    
    if not creds:
        print("[!] No credentials provided to user collector")
        return users, groups, group_memberships
    
    try:
        # Build Admin SDK service
        admin_service = build('admin', 'directory_v1', credentials=creds)
        
        print("[*] User Collector: Enumerating Google Workspace users and groups...")
        
        # Collect users
        users = collect_workspace_users(admin_service)
        
        # Collect groups  
        groups = collect_workspace_groups(admin_service)
        
        # Collect group memberships
        group_memberships = collect_group_memberships(admin_service, groups)
        
        print(f"[+] User Collector: Found {len(users)} users, {len(groups)} groups, {len(group_memberships)} memberships")
        
    except HttpError as e:
        if e.resp.status == 403:
            print("[!] No Google Workspace Admin access - skipping user enumeration")
        elif e.resp.status == 404:
            print("[!] No Google Workspace organization found")
        else:
            print(f"[!] HTTP error during user collection: {e}")
    except Exception as e:
        print(f"[!] Unexpected error during user collection: {e}")
    
    return users, groups, group_memberships

def collect_workspace_users(admin_service):
    """Collect all users from Google Workspace"""
    users = []
    
    try:
        request = admin_service.users().list(customer='my_customer', maxResults=500)
        
        while request:
            response = request.execute()
            
            for user in response.get('users', []):
                user_data = {
                    'id': user.get('id'),
                    'email': user.get('primaryEmail'),
                    'name': user.get('name', {}).get('fullName', ''),
                    'firstName': user.get('name', {}).get('givenName', ''),
                    'lastName': user.get('name', {}).get('familyName', ''),
                    'suspended': user.get('suspended', False),
                    'isAdmin': user.get('isAdmin', False),
                    'isDelegatedAdmin': user.get('isDelegatedAdmin', False),
                    'lastLoginTime': user.get('lastLoginTime', ''),
                    'creationTime': user.get('creationTime', ''),
                    'orgUnitPath': user.get('orgUnitPath', '/'),
                    'isMailboxSetup': user.get('isMailboxSetup', True),
                    'includeInGlobalAddressList': user.get('includeInGlobalAddressList', True),
                    'ipWhitelisted': user.get('ipWhitelisted', False),
                    'recoveryEmail': user.get('recoveryEmail', ''),
                    'recoveryPhone': user.get('recoveryPhone', ''),
                    'changePasswordAtNextLogin': user.get('changePasswordAtNextLogin', False),
                    'agreedToTerms': user.get('agreedToTerms', False),
                    'aliases': user.get('aliases', []),
                    'nonEditableAliases': user.get('nonEditableAliases', [])
                }
                
                # Analyze security risk
                user_data['riskLevel'] = determine_user_risk_level(user_data)
                
                users.append(user_data)
            
            request = admin_service.users().list_next(request, response)
            
        print(f"[+] Collected {len(users)} Google Workspace users")
        
    except Exception as e:
        print(f"[!] Error collecting users: {e}")
    
    return users

def collect_workspace_groups(admin_service):
    """Collect all groups from Google Workspace"""
    groups = []
    
    try:
        request = admin_service.groups().list(customer='my_customer', maxResults=200)
        
        while request:
            response = request.execute()
            
            for group in response.get('groups', []):
                group_data = {
                    'id': group.get('id'),
                    'email': group.get('email'),
                    'name': group.get('name', ''),
                    'description': group.get('description', ''),
                    'directMembersCount': group.get('directMembersCount', 0),
                    'aliases': group.get('aliases', []),
                    'nonEditableAliases': group.get('nonEditableAliases', []),
                    'adminCreated': group.get('adminCreated', False)
                }
                
                # Analyze security risk
                group_data['riskLevel'] = determine_group_risk_level(group_data)
                
                groups.append(group_data)
            
            request = admin_service.groups().list_next(request, response)
            
        print(f"[+] Collected {len(groups)} Google Workspace groups")
        
    except Exception as e:
        print(f"[!] Error collecting groups: {e}")
    
    return groups

def collect_group_memberships(admin_service, groups):
    """Collect memberships for all groups"""
    memberships = []
    
    for group in groups:
        group_email = group.get('email')
        if not group_email:
            continue
            
        try:
            request = admin_service.members().list(groupKey=group_email)
            
            while request:
                response = request.execute()
                
                for member in response.get('members', []):
                    membership = {
                        'groupId': group.get('id'),
                        'groupEmail': group_email,
                        'memberId': member.get('id'),
                        'memberEmail': member.get('email'),
                        'role': member.get('role', 'MEMBER'),  # OWNER, MANAGER, MEMBER
                        'type': member.get('type', 'USER'),   # USER, GROUP, CUSTOMER
                        'status': member.get('status', 'ACTIVE'),
                        'delivery_settings': member.get('delivery_settings', 'ALL_MAIL')
                    }
                    
                    # Analyze membership risk
                    membership['riskLevel'] = determine_membership_risk_level(membership, group)
                    
                    memberships.append(membership)
                
                request = admin_service.members().list_next(request, response)
                
        except HttpError as e:
            if e.resp.status != 403:  # Skip permission denied groups
                print(f"[!] Error collecting memberships for {group_email}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error for group {group_email}: {e}")
    
    print(f"[+] Collected {len(memberships)} group memberships")
    return memberships

def determine_user_risk_level(user_data):
    """Determine risk level for a user"""
    if user_data.get('isAdmin'):
        return 'CRITICAL'
    elif user_data.get('isDelegatedAdmin'):
        return 'HIGH'
    elif user_data.get('suspended'):
        return 'MEDIUM'  # Suspended accounts can be reactivated
    elif any(keyword in user_data.get('email', '').lower() for keyword in ['admin', 'root', 'service']):
        return 'HIGH'
    else:
        return 'LOW'

def determine_group_risk_level(group_data):
    """Determine risk level for a group"""
    group_name = group_data.get('name', '').lower()
    group_email = group_data.get('email', '').lower()
    
    high_risk_keywords = ['admin', 'owner', 'editor', 'manager', 'root', 'security']
    
    if any(keyword in group_name or keyword in group_email for keyword in high_risk_keywords):
        return 'HIGH'
    elif group_data.get('directMembersCount', 0) > 50:
        return 'MEDIUM'  # Large groups pose higher risk
    else:
        return 'LOW'

def determine_membership_risk_level(membership, group):
    """Determine risk level for a group membership"""
    role = membership.get('role', '').upper()
    group_risk = group.get('riskLevel', 'LOW')
    
    if role in ['OWNER', 'MANAGER'] and group_risk in ['HIGH', 'CRITICAL']:
        return 'CRITICAL'
    elif role in ['OWNER', 'MANAGER']:
        return 'HIGH'
    elif group_risk in ['HIGH', 'CRITICAL']:
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_user_privilege_escalation(users, groups, group_memberships):
    """Analyze privilege escalation opportunities through user/group relationships"""
    escalation_paths = []
    
    # Map users to their group memberships
    user_groups = {}
    for membership in group_memberships:
        user_email = membership.get('memberEmail', '')
        if user_email not in user_groups:
            user_groups[user_email] = []
        user_groups[user_email].append(membership)
    
    # Analyze each user's privilege escalation potential
    for user in users:
        user_email = user.get('email', '')
        user_memberships = user_groups.get(user_email, [])
        
        # Check for admin escalation through groups
        admin_groups = [m for m in user_memberships if m.get('riskLevel') in ['HIGH', 'CRITICAL']]
        
        if admin_groups:
            escalation_paths.append({
                'user': user_email,
                'escalationType': 'group_admin_access',
                'adminGroups': [g.get('groupEmail') for g in admin_groups],
                'riskLevel': 'HIGH',
                'description': f"User {user_email} has admin access through {len(admin_groups)} groups"
            })
    
    print(f"[+] Found {len(escalation_paths)} user privilege escalation paths")
    return escalation_paths

def build_user_group_edges(users, groups, group_memberships, current_user):
    """Build BloodHound edges for user/group relationships"""
    edges = []
    
    # User membership edges
    for membership in group_memberships:
        user_email = membership.get('memberEmail')
        group_email = membership.get('groupEmail')
        role = membership.get('role', 'MEMBER')
        
        if user_email and group_email:
            edge_kind = 'MemberOf' if role == 'MEMBER' else f'{role}Of'
            
            edge = {
                "start": {"value": user_email},
                "end": {"value": group_email},
                "kind": edge_kind,
                "properties": {
                    "source": "workspace_membership",
                    "role": role,
                    "riskLevel": membership.get('riskLevel', 'LOW'),
                    "memberType": membership.get('type', 'USER'),
                    "status": membership.get('status', 'ACTIVE'),
                    "description": f"{user_email} is {role} of {group_email}"
                }
            }
            edges.append(edge)
    
    # Admin delegation edges
    for user in users:
        if user.get('isAdmin') or user.get('isDelegatedAdmin'):
            user_email = user.get('email')
            edge = {
                "start": {"value": user_email},
                "end": {"value": "Google Workspace"},
                "kind": "AdminTo",
                "properties": {
                    "source": "workspace_admin",
                    "adminType": "Super Admin" if user.get('isAdmin') else "Delegated Admin",
                    "riskLevel": "CRITICAL",
                    "description": f"{user_email} has admin access to Google Workspace"
                }
            }
            edges.append(edge)
    
    print(f"[+] Built {len(edges)} user/group relationship edges")
    return edges
