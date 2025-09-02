def build_edges(projects, iam_data, users, service_accounts, buckets, secrets):
    """
    Build comprehensive attack path edges from collected GCP data.
    Returns list of edges for BloodHound visualization.
    """
    edges = []
    
    if not projects:
        print("[!] No projects provided to edge builder")
        return edges
    
    print(f"[*] Edge Builder: Processing {len(projects)} projects, {len(iam_data)} IAM policies")
    
    # Build edges from IAM bindings
    iam_edges = build_iam_binding_edges(iam_data, projects)
    edges.extend(iam_edges)
    
    # Build service account relationship edges  
    sa_edges = build_service_account_edges(service_accounts, projects)
    edges.extend(sa_edges)
    
    # Build resource ownership edges
    resource_edges = build_resource_ownership_edges(projects, buckets, secrets, service_accounts)
    edges.extend(resource_edges)
    
    # Build privilege escalation edges
    privesc_edges = build_privilege_escalation_edges(iam_data, service_accounts)
    edges.extend(privesc_edges)
    
    print(f"[+] Edge Builder: Created {len(edges)} attack relationship edges")
    return edges

def build_iam_binding_edges(iam_data, projects):
    """Build edges from IAM policy bindings"""
    edges = []
    
    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId')
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            for member in members:
                # Determine member type and clean ID
                if member.startswith('serviceAccount:'):
                    member_id = member.replace('serviceAccount:', '')
                    member_type = 'ServiceAccount'
                elif member.startswith('user:'):
                    member_id = member.replace('user:', '') 
                    member_type = 'User'
                elif member.startswith('group:'):
                    member_id = member.replace('group:', '')
                    member_type = 'Group'
                else:
                    continue  # Skip unknown member types
                
                # Determine edge type based on role
                edge_kind = determine_edge_kind_from_role(role)
                risk_level = determine_risk_level_from_role(role)
                
                edge = {
                    "start": {"value": member_id},
                    "end": {"value": project_id}, 
                    "kind": edge_kind,
                    "properties": {
                        "source": "iam_binding",
                        "role": role,
                        "riskLevel": risk_level,
                        "memberType": member_type,
                        "projectId": project_id,
                        "description": f"{member_type} has {role} on project {project_id}"
                    }
                }
                edges.append(edge)
    
    print(f"[+] Built {len(edges)} IAM binding edges")
    return edges

def build_service_account_edges(service_accounts, projects):
    """Build edges showing service account relationships"""
    edges = []
    
    for sa in service_accounts:
        sa_email = sa.get('email', '')
        project_id = sa.get('project', '')
        
        if not sa_email or not project_id:
            continue
            
        # Service account belongs to project
        edge = {
            "start": {"value": project_id},
            "end": {"value": sa_email},
            "kind": "Contains",
            "properties": {
                "source": "service_account_ownership",
                "riskLevel": "LOW",
                "description": f"Project {project_id} contains service account {sa_email}"
            }
        }
        edges.append(edge)
        
        # Check for high-risk service accounts
        if any(keyword in sa_email.lower() for keyword in ['admin', 'owner', 'editor']):
            high_risk_edge = {
                "start": {"value": sa_email},
                "end": {"value": project_id},
                "kind": "HighPrivilegeAccess", 
                "properties": {
                    "source": "high_privilege_service_account",
                    "riskLevel": "HIGH",
                    "description": f"High-privilege service account {sa_email} in project {project_id}"
                }
            }
            edges.append(high_risk_edge)
    
    print(f"[+] Built {len(edges)} service account edges")
    return edges

def build_resource_ownership_edges(projects, buckets, secrets, service_accounts):
    """Build edges showing resource ownership and access"""
    edges = []
    
    # Project owns buckets
    for bucket in buckets:
        bucket_name = bucket.get('name', '')
        project_id = bucket.get('project', '')
        
        if bucket_name and project_id:
            edge = {
                "start": {"value": project_id},
                "end": {"value": bucket_name},
                "kind": "Owns",
                "properties": {
                    "source": "resource_ownership", 
                    "resourceType": "Storage Bucket",
                    "riskLevel": "MEDIUM" if bucket.get('publicAccess') else "LOW",
                    "description": f"Project {project_id} owns bucket {bucket_name}"
                }
            }
            edges.append(edge)
    
    # Project owns secrets  
    for secret in secrets:
        secret_name = secret.get('name', '')
        project_id = secret.get('project', '')
        
        if secret_name and project_id:
            edge = {
                "start": {"value": project_id},
                "end": {"value": secret_name},
                "kind": "Owns",
                "properties": {
                    "source": "resource_ownership",
                    "resourceType": "Secret",
                    "riskLevel": "HIGH",  # Secrets are always high risk
                    "description": f"Project {project_id} owns secret {secret_name}"
                }
            }
            edges.append(edge)
    
    print(f"[+] Built {len(edges)} resource ownership edges")
    return edges

def build_privilege_escalation_edges(iam_data, service_accounts):
    """Build edges showing privilege escalation opportunities"""
    edges = []
    
    escalation_permissions = {
        'iam.serviceAccounts.actAs': 'CanImpersonate',
        'iam.serviceAccounts.getAccessToken': 'CanGenerateAccessToken', 
        'iam.serviceAccountKeys.create': 'CanCreateKeys',
        'compute.instances.create': 'CanCreateComputeInstance',
        'cloudfunctions.functions.create': 'CanCreateCloudFunction',
        'deploymentmanager.deployments.create': 'CanCreateDeployment'
    }
    
    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId')
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # Check if role contains escalation permissions
            escalation_perms = get_permissions_for_role(role)
            found_escalation_perms = [p for p in escalation_perms if p in escalation_permissions]
            
            if found_escalation_perms:
                for member in members:
                    member_id = clean_member_id(member)
                    if not member_id:
                        continue
                        
                    for perm in found_escalation_perms:
                        edge_kind = escalation_permissions[perm]
                        
                        edge = {
                            "start": {"value": member_id},
                            "end": {"value": project_id},
                            "kind": edge_kind,
                            "properties": {
                                "source": "privilege_escalation",
                                "permission": perm,
                                "role": role,
                                "riskLevel": "CRITICAL",
                                "description": f"{member_id} can escalate privileges via {perm}"
                            }
                        }
                        edges.append(edge)
    
    print(f"[+] Built {len(edges)} privilege escalation edges")
    return edges

def determine_edge_kind_from_role(role):
    """Determine BloodHound edge type from GCP role"""
    if 'owner' in role.lower():
        return 'Owns'
    elif 'editor' in role.lower():
        return 'CanEdit' 
    elif 'viewer' in role.lower():
        return 'CanView'
    elif 'admin' in role.lower():
        return 'AdminTo'
    else:
        return 'HasRoleOn'

def determine_risk_level_from_role(role):
    """Determine risk level from GCP role"""
    high_risk_roles = ['owner', 'editor', 'admin']
    if any(risk in role.lower() for risk in high_risk_roles):
        return 'HIGH'
    elif 'viewer' in role.lower():
        return 'LOW'
    else:
        return 'MEDIUM'

def get_permissions_for_role(role):
    """Get permissions contained in a GCP role (simplified mapping)"""
    role_permissions = {
        'roles/owner': [
            'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
            'compute.instances.create', 'cloudfunctions.functions.create'
        ],
        'roles/editor': [
            'iam.serviceAccounts.actAs', 'compute.instances.create',
            'cloudfunctions.functions.create'
        ],
        'roles/iam.serviceAccountUser': ['iam.serviceAccounts.actAs'],
        'roles/iam.serviceAccountKeyAdmin': ['iam.serviceAccountKeys.create'],
        'roles/deploymentmanager.editor': ['deploymentmanager.deployments.create']
    }
    return role_permissions.get(role, [])

def clean_member_id(member):
    """Clean member ID from IAM binding format"""
    if member.startswith('serviceAccount:'):
        return member.replace('serviceAccount:', '')
    elif member.startswith('user:'):
        return member.replace('user:', '')
    elif member.startswith('group:'):
        return member.replace('group:', '')
    return None
