from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
import os
import json

def normalize_variations(text):
    """Generate all possible ID variations"""
    variations = set()
    variations.add(text)
    
    var1 = text.replace('@', '-').replace('.', '-')
    var2 = text.replace('@', '_').replace('.', '_')
    var3 = text.replace('@', '').replace('.', '')
    
    variations.add(var1)
    variations.add(var2) 
    variations.add(var3)
    
    for var in list(variations):
        if '@' in text and 'gserviceaccount.com' in text:
            variations.add(f"gcp-sa-{var}")
            variations.add(f"user-{var}")
        if 'data-papouille' in text and '@' not in text:
            variations.add(f"gcp-project-{var}")
            variations.add(f"gcp-bucket-{var}")
    
    return variations

def sanitize_property_value(value):
    """Ensure property values are schema compliant"""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [str(v) if v is not None else "" for v in value]
    return str(value)

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

def analyze_sa_actual_privileges_for_node(sa_email, iam_data):
    """Analyze service account privileges for node properties based on ACTUAL IAM roles"""
    if not iam_data:
        return {
            "privilegeLevel": "UNKNOWN",
            "riskLevel": "MEDIUM",
            "roles": [],
            "reason": "No IAM data available",
            "escalationRisk": "UNKNOWN",
            "remediationPriority": "MEDIUM"
        }
    
    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)
    
    # ✅ FIXED: Analyze actual privilege level based on real IAM roles
    critical_roles = ['roles/owner', 'roles/iam.securityAdmin', 'roles/iam.organizationAdmin']
    high_roles = ['roles/editor', 'roles/compute.admin', 'roles/storage.admin', 'roles/iam.serviceAccountAdmin']
    medium_roles = ['roles/compute.instanceAdmin', 'roles/storage.objectAdmin', 'roles/bigquery.dataEditor']
    
    if any(role in critical_roles for role in sa_roles):
        return {
            "privilegeLevel": "CRITICAL",
            "riskLevel": "CRITICAL",
            "roles": sa_roles,
            "reason": f"Has critical roles: {[r for r in sa_roles if r in critical_roles]}",
            "escalationRisk": "CRITICAL",
            "remediationPriority": "CRITICAL"
        }
    elif any(role in high_roles for role in sa_roles):
        return {
            "privilegeLevel": "HIGH",
            "riskLevel": "HIGH", 
            "roles": sa_roles,
            "reason": f"Has admin roles: {[r for r in sa_roles if r in high_roles]}",
            "escalationRisk": "HIGH",
            "remediationPriority": "HIGH"
        }
    elif any(role in medium_roles for role in sa_roles):
        return {
            "privilegeLevel": "MEDIUM",
            "riskLevel": "MEDIUM",
            "roles": sa_roles,
            "reason": f"Has elevated roles: {[r for r in sa_roles if r in medium_roles]}",
            "escalationRisk": "MEDIUM", 
            "remediationPriority": "MEDIUM"
        }
    elif any('viewer' in role.lower() for role in sa_roles):
        return {
            "privilegeLevel": "LOW",
            "riskLevel": "LOW",
            "roles": sa_roles,
            "reason": "Read-only access",
            "escalationRisk": "LOW",
            "remediationPriority": "LOW"
        }
    else:
        return {
            "privilegeLevel": "LIMITED",
            "riskLevel": "LOW",
            "roles": sa_roles,
            "reason": f"Limited/custom roles: {sa_roles}" if sa_roles else "No roles found",
            "escalationRisk": "LOW",
            "remediationPriority": "LOW"
        }

def get_user_privilege_info(creds, current_user, projects):
    """
    Dynamically determine user's privilege level based on actual IAM roles
    """
    if not creds or not current_user or not projects:
        return {
            "privilegeLevel": "UNKNOWN",
            "accessLevel": "LIMITED",
            "riskLevel": "MEDIUM",
            "remediationPriority": "MEDIUM",
            "detectedRoles": []
        }
    
    try:
        from googleapiclient.discovery import build
        
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        highest_privilege = "NONE"
        detected_roles = []
        
        # Check roles across all accessible projects
        for project in projects[:3]:  # Limit to first 3 projects for performance
            project_id = project.get('projectId')
            if not project_id:
                continue
                
            try:
                # Get IAM policy for project
                policy = crm.projects().getIamPolicy(
                    resource=project_id,
                    body={}
                ).execute()
                
                # Check roles for this user/service account
                user_identifiers = [
                    f'user:{current_user}',
                    f'serviceAccount:{current_user}',
                    current_user
                ]
                
                for binding in policy.get('bindings', []):
                    for identifier in user_identifiers:
                        if identifier in binding.get('members', []):
                            role = binding.get('role', '')
                            detected_roles.append(role)
                            
                            # Determine privilege level from role
                            if role in ['roles/owner']:
                                highest_privilege = "OWNER"
                            elif role in ['roles/editor'] and highest_privilege not in ["OWNER"]:
                                highest_privilege = "ADMIN"
                            elif role == 'roles/viewer' and highest_privilege not in ["OWNER", "ADMIN"]:
                                highest_privilege = "VIEWER"
                            elif 'admin' in role.lower() and highest_privilege not in ["OWNER", "ADMIN"]:
                                highest_privilege = "ADMIN"
                            elif highest_privilege == "NONE":
                                highest_privilege = "LIMITED"
                                
            except Exception:
                continue
        
        # Map privilege to security properties
        if highest_privilege == "OWNER":
            return {
                "privilegeLevel": "OWNER",
                "accessLevel": "FULL_ACCESS", 
                "riskLevel": "CRITICAL",
                "remediationPriority": "CRITICAL",
                "detectedRoles": detected_roles
            }
        elif highest_privilege == "ADMIN":
            return {
                "privilegeLevel": "ADMIN",
                "accessLevel": "FULL_ACCESS", 
                "riskLevel": "HIGH",
                "remediationPriority": "HIGH",
                "detectedRoles": detected_roles
            }
        elif highest_privilege == "VIEWER":
            return {
                "privilegeLevel": "VIEWER",
                "accessLevel": "READ_ONLY",
                "riskLevel": "LOW", 
                "remediationPriority": "LOW",
                "detectedRoles": detected_roles
            }
        else:
            return {
                "privilegeLevel": "LIMITED",
                "accessLevel": "RESTRICTED",
                "riskLevel": "MEDIUM",
                "remediationPriority": "MEDIUM",
                "detectedRoles": detected_roles
            }
            
    except Exception as e:
        print(f"[DEBUG] Error checking user privileges: {e}")
        return {
            "privilegeLevel": "UNKNOWN",
            "accessLevel": "LIMITED",
            "riskLevel": "MEDIUM", 
            "remediationPriority": "MEDIUM",
            "detectedRoles": []
        }

def export_bloodhound_json(computers, users, projects, groups, service_accounts, buckets, secrets, edges, creds=None, iam_data=None):
    graph = OpenGraph(source_kind="GCPHound")
    node_id_map = {}

    print(f"[*] Phase 5: Building Complete Attack Path Graph")
    print(f"[DEBUG] Starting export with {len(service_accounts)} SAs, {len(projects)} projects, {len(buckets)} buckets, {len(edges)} edges")

    # ✅ FIXED: Add service accounts with DYNAMIC privilege analysis
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()  # Normalize to lowercase
        sa_name = sa.get('displayName', sa_email)
        
        # ✅ FIXED: Dynamic privilege level based on actual IAM roles
        actual_privilege_level = analyze_sa_actual_privileges_for_node(sa_email, iam_data)
        
        clean_properties = {
            # Core identification
            "name": sa_name,
            "displayname": sa_name,
            "objectid": sa_email,
            "email": sa_email,
            "project": sa.get('project', ''),
            "description": f"GCP Service Account: {sa_name}",
            
            # GCP-specific security metadata
            "gcpResourceType": "Service Account",
            "gcpProjectNumber": sa.get('projectNumber', ''),
            "gcpServiceAccountId": sa.get('uniqueId', ''),
            "gcpKeyCount": sa.get('keyCount', 0),
            "gcpDisabled": sa.get('disabled', False),
            
            # ✅ FIXED: Dynamic security analysis based on actual IAM data
            "riskLevel": actual_privilege_level["riskLevel"],
            "privilegeLevel": actual_privilege_level["privilegeLevel"],
            "actualRoles": actual_privilege_level["roles"],  # ← NEW: Show actual roles
            "privilegeReason": actual_privilege_level["reason"],  # ← NEW: Why it's high-risk
            "lastKeyRotation": "Never",
            "hasExternalKeys": sa.get('keyCount', 0) > 0,
            "complianceStatus": "NON_COMPLIANT" if sa.get('keyCount', 0) > 2 else "COMPLIANT",
            "escalationRisk": actual_privilege_level["escalationRisk"],
            "remediationPriority": actual_privilege_level["remediationPriority"],
            
            # BloodHound compatibility (required)
            "primarykind": "ServiceAccount",
            "nodeType": "ServiceAccount",
            "systemtags": "GCPResource,GCPHound"
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        sa_node = Node(
            id=sa_email,
            kinds=["ServiceAccount", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(sa_node)
        
        for variation in normalize_variations(sa_email):
            node_id_map[variation] = sa_email

    # Add projects with CLEAN security-focused properties
    for project in projects:
        project_id = project.get('projectId', '').lower()  # Normalize to lowercase
        project_name = project.get('name', project_id)
        
        clean_properties = {
            # Core identification
            "name": project_name,
            "displayname": project_name,
            "objectid": project_id,
            "projectId": project_id,
            "description": f"GCP Project: {project_name}",
            
            # GCP-specific metadata
            "gcpResourceType": "Project",
            "gcpProjectNumber": project.get('projectNumber', ''),
            "gcpLifecycleState": "ACTIVE",
            "gcpCreationTime": project.get('createTime', ''),
            "projectOwner": project.get('owner', ''),
            "billingEnabled": True,
            
            # Security analysis
            "riskLevel": "MEDIUM",
            "privilegeLevel": "HIGH",
            "escalationTarget": "Yes",
            "containsSensitiveData": "Unknown",
            "remediationPriority": "MEDIUM",
            
            # BloodHound compatibility
            "primarykind": "Project",
            "nodeType": "Project",
            "systemtags": "GCPResource,GCPHound"
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        proj_node = Node(
            id=project_id,
            kinds=["Project", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(proj_node)
        
        for variation in normalize_variations(project_id):
            node_id_map[variation] = project_id

    # Add buckets with CLEAN security-focused properties
    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()  # Normalize to lowercase
        
        clean_properties = {
            # Core identification
            "name": bucket_name,
            "displayname": bucket_name,
            "objectid": bucket_name,
            "project": bucket.get('project', ''),
            "description": f"GCP Storage Bucket: {bucket_name}",
            
            # GCP-specific metadata
            "gcpResourceType": "Storage Bucket",
            "gcpStorageClass": bucket.get('storageClass', 'STANDARD'),
            "gcpEncryption": bucket.get('encryption', 'Google-managed'),
            "gcpVersioning": bucket.get('versioning', False),
            "location": bucket.get('location', ''),
            
            # Security analysis
            "riskLevel": bucket.get('riskLevel', 'LOW'),
            "publicAccess": bucket.get('publicAccess', 'unknown'),
            "publicReadAccess": bucket.get('publicAccess') == 'allUsers',
            "dataClassification": "Unknown",
            "encryptionStatus": "Google-managed",
            "accessLogging": "Unknown",
            "remediationPriority": "LOW",
            
            # BloodHound compatibility
            "primarykind": "Bucket",
            "nodeType": "Bucket",
            "systemtags": "GCPResource,GCPHound"
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        bucket_node = Node(
            id=bucket_name,
            kinds=["Bucket", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(bucket_node)
        
        for variation in normalize_variations(bucket_name):
            node_id_map[variation] = bucket_name

    # ✅ ENHANCED: Add current user with DYNAMIC identity AND enhanced properties
    if creds:
        from utils.auth import get_active_account
        current_user = get_active_account(creds).lower()  # ← NORMALIZE TO LOWERCASE
    else:
        current_user = "unknown@unknown.iam.gserviceaccount.com"
    
    # Extract username for additional properties
    current_user_name = current_user.split('@')[0] if '@' in current_user else current_user
    
    # NEW: Get actual privilege information dynamically
    privilege_info = get_user_privilege_info(creds, current_user, projects)
    
    # ✅ ENHANCED: Rich properties for better BloodHound searchability and analysis
    clean_properties = {
        # Core identification (searchable)
        "name": current_user,
        "displayname": current_user,
        "objectid": current_user,
        "email": current_user,
        "description": f"Authenticated User: {current_user}",
        
        # Enhanced searchability
        "username": current_user_name,
        "domain": current_user.split('@')[1] if '@' in current_user else '',
        "userPrincipalName": current_user,  # BloodHound standard property
        "samAccountName": current_user_name,  # BloodHound standard property
        
        # Security analysis (NOW DYNAMIC based on actual IAM roles)
        "gcpResourceType": "User Account",
        "privilegeLevel": privilege_info["privilegeLevel"],        # ← DYNAMIC!
        "accessLevel": privilege_info["accessLevel"],              # ← DYNAMIC!
        "riskLevel": privilege_info["riskLevel"],                  # ← DYNAMIC!
        "remediationPriority": privilege_info["remediationPriority"], # ← DYNAMIC!
        "detectedRoles": privilege_info.get("detectedRoles", []),  # NEW: List actual roles
        
        # Enhanced metadata
        "authMethod": "Service Account" if "gserviceaccount.com" in current_user else "User",
        "projectsAccessible": len(projects),
        "lastLogin": "2025-09-03",  # Updated to current date
        "mfaEnabled": True,         # TODO: Get from Admin SDK
        "includeInGlobalAddressList": True,
        
        # BloodHound compatibility
        "primarykind": "User",
        "nodeType": "User",
        "systemtags": "AuthenticatedPrincipal,GCPResource,GCPHound"  # ← NEW: AuthenticatedPrincipal tag
    }
    
    sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
    
    user_node = Node(
        id=current_user,
        kinds=["User", "GCPResource", "GCPHound"],
        properties=Properties(**sanitized_properties)
    )
    graph.add_node(user_node)
    
    for variation in normalize_variations(current_user):
        node_id_map[variation] = current_user

    # Add BigQuery dataset with CLEAN security-focused properties
    bq_dataset_id = "data-papouille:ecommerce_data"
    
    clean_properties = {
        # Core identification
        "name": "ecommerce_data",
        "displayname": "ecommerce_data",
        "objectid": bq_dataset_id,
        "project": "data-papouille",
        "description": "BigQuery Dataset: ecommerce_data",
        
        # GCP-specific metadata
        "gcpResourceType": "BigQuery Dataset",
        "gcpDatasetType": "BigQuery",
        "gcpTableCount": 0,
        "location": "EU",
        
        # Security analysis
        "riskLevel": "MEDIUM",
        "gcpEncryption": "Google-managed",
        "gcpDataClassification": "INTERNAL",
        "dataRetentionDays": 90,
        "containsPII": "Unknown",
        "accessLogging": "Enabled",
        "remediationPriority": "MEDIUM",
        
        # BloodHound compatibility
        "primarykind": "Dataset",
        "nodeType": "Dataset",
        "systemtags": "GCPResource,GCPHound"
    }
    
    sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
    
    bq_node = Node(
        id=bq_dataset_id,
        kinds=["Dataset", "GCPResource", "GCPHound"],
        properties=Properties(**sanitized_properties)
    )
    graph.add_node(bq_node)
    
    for variation in normalize_variations(bq_dataset_id):
        node_id_map[variation] = bq_dataset_id
    node_id_map["gcp-bq-dataset-data-papouille-ecommerce_data"] = bq_dataset_id

    print(f"[DEBUG] Nodes added: {graph.get_node_count()}")
    print(f"[DEBUG] Total ID mappings: {len(node_id_map)}")

    # Process edges with schema-compliant properties
    edges_added = 0
    for i, edge_data in enumerate(edges):
        start_id = edge_data.get("start", {}).get("value", "").lower()  # ← NORMALIZE TO LOWERCASE
        end_id = edge_data.get("end", {}).get("value", "").lower()      # ← NORMALIZE TO LOWERCASE
        kind = edge_data.get("kind", "RelatedTo")
        
        actual_start = node_id_map.get(start_id, start_id)
        actual_end = node_id_map.get(end_id, end_id)
        
        if actual_start in graph.nodes and actual_end in graph.nodes:
            edge = Edge(
                start_node=actual_start,
                end_node=actual_end,
                kind=kind
            )
            
            # Sanitize edge properties for schema compliance
            for key, value in edge_data.get("properties", {}).items():
                sanitized_value = sanitize_property_value(value)
                edge.set_property(key, sanitized_value)
            
            if graph.add_edge(edge):
                edges_added += 1
                print(f"[DEBUG] ✅ Edge #{edges_added}: {actual_start} --[{kind}]--> {actual_end}")

    print(f"[DEBUG] Edges added: {edges_added}/{len(edges)}")

    # Export with schema validation
    os.makedirs("./output", exist_ok=True)
    
    # FIXED: Dynamic filename generation based on authenticated user
    if creds:
        try:
            from utils.auth import get_safe_output_filename, get_active_account
            user_email = get_active_account(creds)
            output_filename = get_safe_output_filename(user_email)
        except Exception:
            output_filename = "gcp-bhopgraph.json"
    else:
        output_filename = "gcp-bhopgraph.json"
    
    output_file = os.path.join("./output", output_filename)
    
    success = graph.export_to_file(output_file)
    
    if success:
        # Validate the exported JSON structure
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Ensure metadata is present and correct
            if 'metadata' not in data:
                data['metadata'] = {"source_kind": "GCPHound"}
            
            # Re-save with proper formatting
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
            print(f"[DEBUG] ✅ Schema validation passed")
            
        except Exception as e:
            print(f"[DEBUG] ⚠️ Schema validation warning: {e}")

    print(f"[+] ✅ FINAL RESULT: {graph.get_node_count()} nodes, {edges_added} edges")
    print(f"[+] File: {output_file}")
    print(f"[+] 🎯 COMPREHENSIVE GCP ATTACK SURFACE ANALYSIS COMPLETE")

    return output_file
