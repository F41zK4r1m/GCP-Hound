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
    
    # ✅ FIXED: Pass iam_data for dynamic privilege analysis
    sa_edges = build_service_account_edges(service_accounts, projects, iam_data)
    edges.extend(sa_edges)
    
    # Build resource ownership edges
    resource_edges = build_resource_ownership_edges(projects, buckets, secrets, service_accounts)
    edges.extend(resource_edges)
    
    # Build privilege escalation edges
    privesc_edges = build_privilege_escalation_edges(iam_data, service_accounts)
    edges.extend(privesc_edges)
    
    print(f"[+] Edge Builder: Created {len(edges)} attack relationship edges")
    return edges

def get_sa_roles_from_iam(sa_email, iam_data):
    """Extract actual roles assigned to service account from IAM data"""
    sa_roles = []
    
    if not iam_data:
        return sa_roles
    
    service_account_identifier = f"serviceAccount:{sa_email}"
    
    for iam_policy in iam_data:
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            members = binding.get('members', [])
            role = binding.get('role', '')
            
            if service_account_identifier in members:
                sa_roles.append(role)
    
    return sa_roles

def analyze_sa_actual_privileges(sa_email, iam_data):
    """Analyze service account's ACTUAL privilege level from IAM data"""
    if not iam_data:
        return "UNKNOWN"
    
    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)
    
    # ✅ FIXED: Check actual roles, not naming patterns
    critical_roles = ['roles/owner', 'roles/iam.securityAdmin', 'roles/iam.organizationAdmin']
    high_roles = ['roles/editor', 'roles/compute.admin', 'roles/storage.admin', 'roles/iam.serviceAccountAdmin']
    medium_roles = ['roles/compute.instanceAdmin', 'roles/storage.objectAdmin', 'roles/bigquery.dataEditor']
    
    if any(role in critical_roles for role in sa_roles):
        return "CRITICAL"
    elif any(role in high_roles for role in sa_roles):
        return "HIGH"
    elif any(role in medium_roles for role in sa_roles):
        return "MEDIUM"
    elif any('viewer' in role.lower() for role in sa_roles):
        return "LOW"
    else:
        return "LIMITED"

def get_privilege_reason(sa_email, iam_data):
    """Get human-readable reason why service account is considered high-privilege"""
    roles = get_sa_roles_from_iam(sa_email, iam_data)
    
    critical_roles = [r for r in roles if r in ['roles/owner', 'roles/iam.securityAdmin']]
    admin_roles = [r for r in roles if 'admin' in r.lower()]
    
    if critical_roles:
        return f"Has critical roles: {', '.join(critical_roles)}"
    elif admin_roles:
        return f"Has admin roles: {', '.join(admin_roles)}"
    elif len(roles) > 3:
        return f"Has multiple roles ({len(roles)}): {', '.join(roles[:3])}..."
    elif roles:
        return f"Has roles: {', '.join(roles)}"
    else:
        return "No roles found"

def build_service_account_edges(service_accounts, projects, iam_data=None):
    """Build service account relationship edges with DYNAMIC privilege analysis"""
    edges = []
    
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        project_id = sa.get('project', '').lower()
        
        if not sa_email or not project_id:
            continue
            
        # Basic containment edge
        edge = {
            "start": {"value": project_id},
            "end": {"value": sa_email},
            "kind": "ContainsServiceAccount",
            "properties": {
                "source": "service_account_ownership",
                "riskLevel": "LOW",
                "keyCount": sa.get('keyCount', 0),
                "disabled": sa.get('disabled', False),
                "description": f"Project {project_id} contains service account {sa_email}"
            }
        }
        edges.append(edge)
        
        # ✅ FIXED: Dynamic privilege analysis based on ACTUAL IAM roles
        actual_privilege_level = analyze_sa_actual_privileges(sa_email, iam_data)
        
        # Only create high-privilege edge if ACTUALLY high-privileged
        if actual_privilege_level in ['CRITICAL', 'HIGH']:
            high_privilege_edge = {
                "start": {"value": sa_email},
                "end": {"value": project_id},
                "kind": "HighPrivilegeServiceAccount",
                "properties": {
                    "source": "iam_privilege_analysis",  # ← Now based on IAM, not naming
                    "riskLevel": actual_privilege_level,
                    "actualRoles": get_sa_roles_from_iam(sa_email, iam_data),
                    "privilegeReason": get_privilege_reason(sa_email, iam_data),
                    "description": f"Service account {sa_email} has {actual_privilege_level} privileges based on IAM roles"
                }
            }
            edges.append(high_privilege_edge)
    
    print(f"[+] Built {len(edges)} service account edges (privilege analysis: {'IAM-based' if iam_data else 'limited'})")
    return edges

def build_enhanced_privilege_edges(current_user, outbound_permissions):
    """Build detailed privilege edges showing specific allowed operations"""
    edges = []
    
    # ✅ ENHANCED: More descriptive edge types for specific GCP permissions
    permission_edge_mapping = {
        'storage.objects.create': 'CanCreateStorageObjects',
        'storage.objects.delete': 'CanDeleteStorageObjects',
        'storage.objects.get': 'CanReadStorageObjects',
        'storage.buckets.create': 'CanCreateStorageBuckets',
        'storage.buckets.delete': 'CanDeleteStorageBuckets',
        'storage.buckets.getIamPolicy': 'CanReadBucketPolicy',
        'storage.buckets.setIamPolicy': 'CanModifyBucketPolicy',
        
        'compute.instances.start': 'CanStartInstances',
        'compute.instances.stop': 'CanStopInstances',
        'compute.instances.create': 'CanCreateInstances',
        'compute.instances.delete': 'CanDeleteInstances',
        'compute.instances.setMetadata': 'CanModifyInstanceMetadata',
        'compute.instances.setServiceAccount': 'CanChangeInstanceServiceAccount',
        
        'iam.serviceAccounts.actAs': 'CanImpersonate',
        'iam.serviceAccounts.getAccessToken': 'CanGenerateAccessToken',
        'iam.serviceAccountKeys.create': 'CanCreateKeys',
        'iam.serviceAccountKeys.delete': 'CanDeleteKeys',
        'iam.serviceAccountKeys.get': 'CanReadKeys',
        'iam.serviceAccountKeys.list': 'CanListKeys',
        
        'bigquery.datasets.create': 'CanCreateBQDatasets',
        'bigquery.datasets.get': 'CanAccessBQDatasets', 
        'bigquery.jobs.create': 'CanRunBQJobs',
        'bigquery.tables.create': 'CanCreateBQTables',
        'bigquery.tables.getData': 'CanReadBQData',
        
        'cloudfunctions.functions.create': 'CanCreateCloudFunctions',
        'cloudfunctions.functions.call': 'CanInvokeCloudFunctions',
        'cloudfunctions.functions.sourceCodeSet': 'CanModifyFunctionCode',
        
        'resourcemanager.projects.get': 'CanReadProject',
        'resourcemanager.projects.getIamPolicy': 'CanReadProjectPolicy',
        'resourcemanager.projects.setIamPolicy': 'CanModifyProjectPolicy',
        
        'secretmanager.secrets.create': 'CanCreateSecrets',
        'secretmanager.versions.access': 'CanAccessSecrets'
    }
    
    # ✅ ENHANCED: Risk level mapping for permissions
    risk_mapping = {
        'CanImpersonate': 'CRITICAL',
        'CanCreateKeys': 'CRITICAL', 
        'CanModifyProjectPolicy': 'CRITICAL',
        'CanModifyBucketPolicy': 'CRITICAL',
        'CanChangeInstanceServiceAccount': 'CRITICAL',
        'CanCreateCloudFunctions': 'HIGH',
        'CanCreateInstances': 'HIGH',
        'CanModifyFunctionCode': 'HIGH',
        'CanDeleteStorageObjects': 'HIGH',
        'CanAccessSecrets': 'HIGH'
    }
    
    for project_perms in outbound_permissions:
        project_id = project_perms.get('projectId', '').lower()
        permissions = project_perms.get('permissions', [])
        
        for permission in permissions:
            if permission in permission_edge_mapping:
                edge_kind = permission_edge_mapping[permission]
                risk_level = risk_mapping.get(edge_kind, 'MEDIUM')
                
                edge = {
                    "start": {"value": current_user.lower()},
                    "end": {"value": project_id},
                    "kind": edge_kind,
                    "properties": {
                        "source": "gcp_privilege_analysis",
                        "permission": permission,
                        "riskLevel": risk_level,
                        "attackVector": get_attack_vector_for_permission(permission),
                        "mitreTechnique": get_mitre_technique_for_permission(permission),
                        "description": f"User can {permission.replace('.', ' ')} in project {project_id}"
                    }
                }
                edges.append(edge)
    
    return edges

def get_attack_vector_for_permission(permission):
    """Map GCP permissions to attack vectors"""
    attack_vectors = {
        'iam.serviceAccounts.actAs': 'Service Account Impersonation',
        'iam.serviceAccountKeys.create': 'Service Account Key Creation', 
        'compute.instances.create': 'Compute Instance Privilege Escalation',
        'compute.instances.setServiceAccount': 'Instance Service Account Hijacking',
        'cloudfunctions.functions.create': 'Serverless Code Execution',
        'cloudfunctions.functions.sourceCodeSet': 'Function Code Injection',
        'storage.objects.delete': 'Data Destruction',
        'storage.buckets.setIamPolicy': 'Bucket Policy Manipulation',
        'bigquery.datasets.create': 'Data Exfiltration Setup',
        'bigquery.tables.getData': 'Data Exfiltration',
        'secretmanager.versions.access': 'Credential Harvesting',
        'resourcemanager.projects.setIamPolicy': 'Project Policy Takeover'
    }
    return attack_vectors.get(permission, 'Resource Manipulation')

def get_mitre_technique_for_permission(permission):
    """Map GCP permissions to MITRE ATT&CK techniques"""
    mitre_mapping = {
        'iam.serviceAccounts.actAs': 'T1078.004',  # Valid Accounts: Cloud Accounts
        'iam.serviceAccountKeys.create': 'T1098.001',  # Account Manipulation: Additional Cloud Credentials
        'compute.instances.create': 'T1578.002',  # Modify Cloud Compute Infrastructure: Create Cloud Instance
        'cloudfunctions.functions.create': 'T1578.001',  # Modify Cloud Compute Infrastructure: Create Snapshot
        'storage.objects.delete': 'T1485',  # Data Destruction
        'bigquery.tables.getData': 'T1530',  # Data from Cloud Storage Object
        'secretmanager.versions.access': 'T1555.006'  # Credentials from Password Stores: Cloud Secrets Management Stores
    }
    return mitre_mapping.get(permission, '')

def build_iam_binding_edges(iam_data, projects):
    """Build edges from IAM policy bindings with enhanced descriptions"""
    edges = []
    
    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId', '').lower()
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            for member in members:
                # Determine member type and clean ID
                if member.startswith('serviceAccount:'):
                    member_id = member.replace('serviceAccount:', '').lower()
                    member_type = 'ServiceAccount'
                elif member.startswith('user:'):
                    member_id = member.replace('user:', '').lower()
                    member_type = 'User'
                elif member.startswith('group:'):
                    member_id = member.replace('group:', '').lower()
                    member_type = 'Group'
                else:
                    continue  # Skip unknown member types
                
                # ✅ ENHANCED: More descriptive edge types based on role
                edge_kind = determine_enhanced_edge_kind_from_role(role)
                risk_level = determine_risk_level_from_role(role)
                
                edge = {
                    "start": {"value": member_id},
                    "end": {"value": project_id}, 
                    "kind": edge_kind,
                    "properties": {
                        "source": "iam_policy_binding",
                        "role": role,
                        "riskLevel": risk_level,
                        "memberType": member_type,
                        "projectId": project_id,
                        "attackSurface": get_attack_surface_for_role(role),
                        "description": f"{member_type} {member_id} has {role} on project {project_id}"
                    }
                }
                edges.append(edge)
    
    print(f"[+] Built {len(edges)} enhanced IAM binding edges")
    return edges

def determine_enhanced_edge_kind_from_role(role):
    """Determine enhanced BloodHound edge type from GCP role"""
    role_lower = role.lower()
    
    if 'owner' in role_lower:
        return 'OwnsProject'
    elif 'editor' in role_lower:
        return 'CanEditProject' 
    elif 'viewer' in role_lower:
        return 'CanViewProject'
    elif 'admin' in role_lower:
        return 'AdministerProject'
    elif 'security' in role_lower:
        return 'ManageProjectSecurity'
    elif 'iam' in role_lower:
        return 'ManageProjectIAM'
    elif 'compute' in role_lower:
        return 'ManageProjectCompute'
    elif 'storage' in role_lower:
        return 'ManageProjectStorage'
    elif 'bigquery' in role_lower:
        return 'ManageProjectBigQuery'
    else:
        return 'HasRoleOnProject'

def get_attack_surface_for_role(role):
    """Get attack surface description for GCP role"""
    attack_surfaces = {
        'roles/owner': 'Full project control including IAM, billing, and resource management',
        'roles/editor': 'Resource creation/modification without IAM management',
        'roles/viewer': 'Read-only access to project resources',
        'roles/iam.securityAdmin': 'IAM policy management and security configuration',
        'roles/compute.admin': 'Compute Engine instances and infrastructure control',
        'roles/storage.admin': 'Cloud Storage buckets and objects management',
        'roles/bigquery.admin': 'BigQuery datasets, jobs, and data access'
    }
    return attack_surfaces.get(role, 'Specialized role-based access to project resources')

def determine_risk_level_from_role(role):
    """Determine risk level from GCP role with enhanced granularity"""
    role_lower = role.lower()
    
    critical_roles = ['owner', 'securityadmin', 'iam.admin']
    high_risk_roles = ['editor', 'admin', 'compute.admin', 'storage.admin']
    medium_risk_roles = ['dataviewer', 'bigquery.user', 'cloudsql.client']
    
    if any(critical in role_lower for critical in critical_roles):
        return 'CRITICAL'
    elif any(high in role_lower for high in high_risk_roles):
        return 'HIGH'
    elif any(medium in role_lower for medium in medium_risk_roles):
        return 'MEDIUM'
    elif 'viewer' in role_lower:
        return 'LOW'
    else:
        return 'MEDIUM'

def build_resource_ownership_edges(projects, buckets, secrets, service_accounts):
    """Build enhanced resource ownership and access edges"""
    edges = []
    
    # ✅ ENHANCED: Project owns buckets with risk assessment
    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()
        project_id = bucket.get('project', '').lower()
        
        if bucket_name and project_id:
            # Determine risk level based on bucket properties
            is_public = bucket.get('publicAccess') == 'allUsers'
            has_versioning = bucket.get('versioning', False)
            risk_level = "CRITICAL" if is_public else ("LOW" if has_versioning else "MEDIUM")
            
            edge = {
                "start": {"value": project_id},
                "end": {"value": bucket_name},
                "kind": "OwnsStorageBucket",
                "properties": {
                    "source": "resource_ownership", 
                    "resourceType": "Storage Bucket",
                    "riskLevel": risk_level,
                    "publicAccess": bucket.get('publicAccess', 'unknown'),
                    "versioning": has_versioning,
                    "location": bucket.get('location', ''),
                    "description": f"Project {project_id} owns storage bucket {bucket_name}"
                }
            }
            edges.append(edge)
    
    # ✅ ENHANCED: Project owns secrets with high risk classification
    for secret in secrets:
        secret_name = secret.get('name', '').lower()
        project_id = secret.get('project', '').lower()
        
        if secret_name and project_id:
            edge = {
                "start": {"value": project_id},
                "end": {"value": secret_name},
                "kind": "OwnsSecret",
                "properties": {
                    "source": "resource_ownership",
                    "resourceType": "Secret",
                    "riskLevel": "HIGH",  # Secrets are always high risk
                    "encryptionStatus": "Google-managed",
                    "description": f"Project {project_id} owns secret {secret_name}"
                }
            }
            edges.append(edge)
    
    print(f"[+] Built {len(edges)} enhanced resource ownership edges")
    return edges

def build_privilege_escalation_edges(iam_data, service_accounts):
    """Build enhanced privilege escalation opportunity edges"""
    edges = []
    
    # ✅ ENHANCED: More comprehensive escalation permission mapping
    escalation_permissions = {
        'iam.serviceAccounts.actAs': 'CanImpersonate',
        'iam.serviceAccounts.getAccessToken': 'CanGenerateAccessToken', 
        'iam.serviceAccountKeys.create': 'CanCreateKeys',
        'iam.serviceAccountKeys.get': 'CanReadKeys',
        'compute.instances.create': 'CanCreateComputeInstance',
        'compute.instances.setServiceAccount': 'CanChangeInstanceServiceAccount',
        'cloudfunctions.functions.create': 'CanCreateCloudFunction',
        'cloudfunctions.functions.sourceCodeSet': 'CanModifyFunctionCode',
        'deploymentmanager.deployments.create': 'CanCreateDeployment',
        'resourcemanager.projects.setIamPolicy': 'CanModifyProjectPolicy',
        'storage.buckets.setIamPolicy': 'CanModifyBucketPolicy'
    }
    
    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId', '').lower()
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # ✅ ENHANCED: Get permissions for role with better mapping
            escalation_perms = get_enhanced_permissions_for_role(role)
            found_escalation_perms = [p for p in escalation_perms if p in escalation_permissions]
            
            if found_escalation_perms:
                for member in members:
                    member_id = clean_member_id(member)
                    if not member_id:
                        continue
                        
                    for perm in found_escalation_perms:
                        edge_kind = escalation_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        
                        edge = {
                            "start": {"value": member_id},
                            "end": {"value": project_id},
                            "kind": edge_kind,
                            "properties": {
                                "source": "privilege_escalation_analysis",
                                "permission": perm,
                                "role": role,
                                "riskLevel": risk_level,
                                "mitreTechnique": get_mitre_technique_for_permission(perm),
                                "attackVector": get_attack_vector_for_permission(perm),
                                "description": f"{member_id} can escalate privileges via {perm} in {project_id}"
                            }
                        }
                        edges.append(edge)
    
    print(f"[+] Built {len(edges)} enhanced privilege escalation edges")
    return edges

def get_enhanced_permissions_for_role(role):
    """Get comprehensive permissions contained in a GCP role"""
    role_permissions = {
        'roles/owner': [
            'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
            'compute.instances.create', 'cloudfunctions.functions.create',
            'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy'
        ],
        'roles/editor': [
            'iam.serviceAccounts.actAs', 'compute.instances.create',
            'cloudfunctions.functions.create', 'compute.instances.setServiceAccount'
        ],
        'roles/iam.serviceAccountUser': ['iam.serviceAccounts.actAs'],
        'roles/iam.serviceAccountKeyAdmin': ['iam.serviceAccountKeys.create', 'iam.serviceAccountKeys.get'],
        'roles/iam.securityAdmin': ['iam.serviceAccounts.actAs', 'resourcemanager.projects.setIamPolicy'],
        'roles/compute.admin': ['compute.instances.create', 'compute.instances.setServiceAccount'],
        'roles/storage.admin': ['storage.buckets.setIamPolicy'],
        'roles/deploymentmanager.editor': ['deploymentmanager.deployments.create']
    }
    return role_permissions.get(role, [])

def get_escalation_risk_level(permission):
    """Get risk level for escalation permission"""
    critical_perms = [
        'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
        'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy'
    ]
    high_perms = [
        'compute.instances.create', 'cloudfunctions.functions.create',
        'compute.instances.setServiceAccount', 'cloudfunctions.functions.sourceCodeSet'
    ]
    
    if permission in critical_perms:
        return 'CRITICAL'
    elif permission in high_perms:
        return 'HIGH'
    else:
        return 'MEDIUM'

def clean_member_id(member):
    """Clean member ID from IAM binding format"""
    if member.startswith('serviceAccount:'):
        return member.replace('serviceAccount:', '').lower()
    elif member.startswith('user:'):
        return member.replace('user:', '').lower()
    elif member.startswith('group:'):
        return member.replace('group:', '').lower()
    return None
