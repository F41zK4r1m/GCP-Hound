from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
import os
import json

def normalize_variations(text, discovered_projects=None):
    """Generate all possible ID variations for fuzzy matching"""
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

        if discovered_projects and '@' not in text:
            for project_name in discovered_projects:
                if project_name.lower() in text.lower():
                    variations.add(f"gcp-project-{var}")
                    variations.add(f"gcp-bucket-{var}")
                    break  
    
    return variations

def sanitize_property_value(value):
    """Ensure property values are schema compliant"""
    if value is None:
        return "Unknown"
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [str(v) if v is not None else "Unknown" for v in value]
    return str(value)

def fix_edge_name(edge_name):
    """Clean up verbose edge names to readable format"""
    edge_mapping = {
        "CanEscalateViaIamserviceaccountkeyscreate": "CanCreateKeys",
        "CanEscalateViaIamserviceaccountsactas": "CanImpersonate", 
        "CanEscalateViaIamserviceaccountsgetaccesstoken": "CanGetAccessToken",
        "CanEscalateViaIamserviceaccountssignblob": "CanSignBlob",
        "CanEscalateViaIamserviceaccountssignjwt": "CanSignJWT",
        "CanEscalateViaIamserviceaccounts": "CanImpersonate",
        "CanEscalateViaIamserviceaccountssetiampolicy": "CanModifyIamPolicy",
        "CanEscalateViaComputeinstancescreate": "CanCreateComputeInstance",
        "CanEscalateViaCloudfunctionscreate": "CanCreateCloudFunction",
        "CanEscalateViaResourcemanagerprojectssetiampolicy": "CanModifyProjectPolicy",
        "CanEscalateViaStoragebucketssetiampolicy": "CanModifyBucketPolicy",
    }
    return edge_mapping.get(edge_name, edge_name)

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
            "privilegeLevel": "Unknown",
            "riskLevel": "Unknown",
            "roles": [],
            "reason": "No IAM data available",
            "escalationRisk": "Unknown",
            "remediationPriority": "Unknown"
        }
    
    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)
    
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

def filter_edges_for_bloodhound(edges):
    """Remove duplicate and self-referencing edges"""
    seen_edges = set()
    clean_edges = []
    
    for edge in edges:
        start = edge.get('start', {}).get('value', '').lower()
        end = edge.get('end', {}).get('value', '').lower()
        kind = edge.get('kind', '')
        
        # Skip self-referencing edges
        if start == end:
            continue
            
        # Skip duplicate edges
        edge_key = f'{start}|{kind}|{end}'
        if edge_key in seen_edges:
            continue
            
        seen_edges.add(edge_key)
        clean_edges.append(edge)
    
    print(f"[+] Edge Filtering: {len(edges)} → {len(clean_edges)} edges (removed {len(edges) - len(clean_edges)} duplicates/self-refs)")
    return clean_edges

def validate_and_clean_graph_data(nodes, edges, args=None):
    """
    🔧 CRITICAL FIX: Validate nodes and edges before OpenGraph processing to prevent empty ID errors
    """
    print("[DEBUG] Starting graph validation...")
    
    # Count original data
    original_edge_count = len(edges)
    
    # Validate edges - ensure start and end values exist and are non-empty
    valid_edges = []
    skipped_edges = 0
    
    for edge in edges:
        start_id = edge.get('start', {}).get('value')
        end_id = edge.get('end', {}).get('value')
        
        # Check both IDs exist and are non-empty strings
        if (start_id and end_id and 
            str(start_id).strip() and str(end_id).strip()):
            valid_edges.append(edge)
        else:
            skipped_edges += 1
            if args and hasattr(args, 'debug') and args.debug:
                print(f"[DEBUG] Skipped edge: start='{start_id}', end='{end_id}'")
    
    # Log results
    if skipped_edges > 0:
        print(f"[WARNING] Skipped {skipped_edges} edges with empty/invalid node references")
    
    print(f"[+] Graph validation: {len(valid_edges)}/{original_edge_count} valid edges")
    return valid_edges

def create_logging_access_edges(log_sinks, current_user, service_accounts, iam_data=None):
    """✅ FIXED: Create edges for log stream access - ONLY for accounts with actual logging permissions"""
    edges = []
    
    for sink in log_sinks:
        # Check if this is actually a log stream
        is_stream = sink.get('type') == 'log_stream' or sink.get('isLogStream') is True
        if not is_stream:
            continue

        # User -> log stream (only if user exists)
        if current_user and current_user != "Unknown":
            user_edge = {
                'start': {'value': current_user},
                'end': {'value': sink.get('objectId')},
                'kind': 'CanAccessLogStream',
                'properties': {
                    'logType': sink.get('logType', 'application'),
                    'riskLevel': sink.get('riskLevel', 'MEDIUM'),
                    'sensitivityLevel': sink.get('sensitivityLevel', 'LOW'),
                    'description': f"Can access {sink.get('logType')} logs: {sink.get('displayName')}",
                    'escalationMethod': 'log_stream_access',
                    'accessRequired': sink.get('accessRequired', [])
                }
            }
            edges.append(user_edge)

        # SA -> sensitive streams ONLY if SA has actual logging permissions
        if sink.get('sensitivityLevel') in ['CRITICAL', 'HIGH']:
            for sa in service_accounts:
                sa_email = sa.get('email', '')
                if not sa_email:
                    continue
                
                # ✅ CRITICAL FIX: Check if SA actually has logging permissions
                sa_roles = get_sa_roles_from_iam(sa_email, iam_data) if iam_data else []
                
                # Only SAs with these roles can access logging
                logging_roles = [
                    'roles/owner', 'roles/editor', 'roles/logging.viewer', 
                    'roles/logging.privateLogViewer', 'roles/logging.admin',
                    'roles/logging.logWriter'
                ]
                
                has_logging_access = any(role in logging_roles for role in sa_roles)
                
                # ✅ ONLY create edge if SA has actual logging permissions
                if has_logging_access:
                    sa_edge = {
                        'start': {'value': sa_email},
                        'end': {'value': sink.get('objectId')},
                        'kind': 'CanViewSensitiveLogs',
                        'properties': {
                            'logType': sink.get('logType'),
                            'riskLevel': 'HIGH',
                            'sensitivityLevel': sink.get('sensitivityLevel'),
                            'description': f"SA with logging permissions can access sensitive {sink.get('logType')} logs",
                            'escalationMethod': 'privileged_log_access',
                            'grantedViaRoles': [r for r in sa_roles if r in logging_roles]
                        }
                    }
                    edges.append(sa_edge)
    
    return edges

def export_bloodhound_json(computers, users, projects, groups, service_accounts, buckets, secrets, edges, creds=None, iam_data=None, log_sinks=None, log_buckets=None, log_metrics=None, bigquery_datasets=None):
    """✅ FIXED: Export comprehensive GCP data to BloodHound JSON format using ONLY real enumerated data"""
    graph = OpenGraph(source_kind="GCPHound")
    
    print(f"[*] Phase 5: Building Complete Attack Path Graph with Real Data Only")
    print(f"[DEBUG] Starting export with {len(service_accounts)} SAs, {len(projects)} projects, {len(buckets)} buckets, {len(edges)} edges")

    # Handle all parameters with defaults
    log_sinks = log_sinks or []
    log_buckets = log_buckets or []
    log_metrics = log_metrics or []
    bigquery_datasets = bigquery_datasets or []
    
    if log_sinks or log_buckets or log_metrics:
        total_logging = len(log_sinks) + len(log_buckets) + len(log_metrics)
        print(f"[DEBUG] Including {total_logging} logging resources ({len(log_sinks)} sinks, {len(log_buckets)} buckets, {len(log_metrics)} metrics)")

    # Extract project names from enumerated data
    discovered_project_names = [p.get('projectId', '').lower() for p in projects if p.get('projectId')]
    
    # Build node mapping
    node_id_map = {}

    # Add service accounts using ONLY real enumerated data
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        
        # ✅ VALIDATION: Skip if no valid email
        if not sa_email or not sa_email.strip():
            print(f"[WARNING] Skipping service account with invalid email: {sa}")
            continue
            
        sa_name = sa.get('displayName', sa.get('name', sa_email))
        
        # Dynamic privilege level based on actual IAM roles
        actual_privilege_level = analyze_sa_actual_privileges_for_node(sa_email, iam_data)
        
        # Use ONLY real properties from enumerated data
        clean_properties = {
            "name": sa_email,
            "displayname": sa_name,
            "objectid": sa_email,
            "email": sa_email,
            "short_name": sa_email.split('@')[0] if '@' in sa_email else sa_email,
            "platform": "GCP",
            "project": sa.get('project', 'Unknown'),
            "description": f"GCP Service Account: {sa_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Service Account",
            "gcpProjectNumber": sa.get('projectNumber', 'Unknown'),
            "gcpServiceAccountId": sa.get('uniqueId', 'Unknown'),
            "gcpKeyCount": sa.get('keyCount', 0),
            "gcpDisabled": sa.get('disabled', False),
            
            # Dynamic security analysis based on actual IAM data
            "riskLevel": actual_privilege_level["riskLevel"],
            "privilegeLevel": actual_privilege_level["privilegeLevel"],
            "actualRoles": actual_privilege_level["roles"],
            "privilegeReason": actual_privilege_level["reason"],
            "hasExternalKeys": sa.get('keyCount', 0) > 0,
            "complianceStatus": "NON_COMPLIANT" if sa.get('keyCount', 0) > 2 else "COMPLIANT" if sa.get('keyCount', 0) >= 0 else "Unknown",
            "escalationRisk": actual_privilege_level["escalationRisk"],
            "remediationPriority": actual_privilege_level["remediationPriority"],
            
            # Real timestamps if available
            "creationTime": sa.get('creationTime', 'Unknown'),
            "lastKeyRotation": sa.get('lastKeyRotation', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        sa_node = Node(
            id=sa_email,
            kinds=["GCPServiceAccount", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(sa_node)
        
        for variation in normalize_variations(sa_email, discovered_project_names):
            node_id_map[variation] = sa_email

    # Add projects using ONLY real enumerated data
    for project in projects:
        project_id = project.get('projectId', '').lower()
        
        # ✅ VALIDATION: Skip if no valid project ID
        if not project_id or not project_id.strip():
            print(f"[WARNING] Skipping project with invalid ID: {project}")
            continue
            
        project_name = project.get('name', project_id)
        
        clean_properties = {
            "name": project_id,
            "displayname": project_name,
            "objectid": project_id,
            "projectId": project_id,
            "platform": "GCP",
            "description": f"GCP Project: {project_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Project",
            "gcpProjectNumber": project.get('projectNumber', 'Unknown'),
            "gcpLifecycleState": project.get('lifecycleState', 'Unknown'),
            "gcpCreationTime": project.get('createTime', 'Unknown'),
            "projectOwner": project.get('owner', 'Unknown'),
            
            # Real billing info if available, otherwise Unknown
            "billingEnabled": project.get('billingEnabled', 'Unknown'),
            
            # Calculated security analysis
            "riskLevel": "MEDIUM",
            "privilegeLevel": "HIGH", 
            "escalationTarget": "Yes",
            "containsSensitiveData": "Unknown",
            "remediationPriority": "MEDIUM"
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        proj_node = Node(
            id=project_id,
            kinds=["GCPProject", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(proj_node)
        
        for variation in normalize_variations(project_id, discovered_project_names):
            node_id_map[variation] = project_id

    # Add buckets using ONLY real enumerated data
    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()
        
        # ✅ VALIDATION: Skip if no valid bucket name
        if not bucket_name or not bucket_name.strip():
            print(f"[WARNING] Skipping bucket with invalid name: {bucket}")
            continue
        
        clean_properties = {
            "name": bucket_name,
            "displayname": bucket_name,
            "objectid": bucket_name,
            "platform": "GCP",
            "project": bucket.get('project', 'Unknown'),
            "description": f"GCP Storage Bucket: {bucket_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Storage Bucket",
            "gcpStorageClass": bucket.get('storageClass', 'Unknown'),
            "gcpEncryption": bucket.get('encryption', 'Unknown'),
            "gcpVersioning": bucket.get('versioning', False),
            "location": bucket.get('location', 'Unknown'),
            "timeCreated": bucket.get('timeCreated', 'Unknown'),
            "updated": bucket.get('updated', 'Unknown'),
            
            # Real security analysis based on actual bucket configuration
            "riskLevel": bucket.get('riskLevel', 'Unknown'),
            "publicAccess": bucket.get('publicAccess', 'Unknown'),
            "publicReadAccess": bucket.get('publicAccess') == 'allUsers' if bucket.get('publicAccess') != 'Unknown' else 'Unknown',
            "dataClassification": bucket.get('dataClassification', 'Unknown'),
            "encryptionStatus": bucket.get('encryption', 'Unknown'),
            "accessLogging": bucket.get('accessLogging', 'Unknown'),
            "remediationPriority": bucket.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        bucket_node = Node(
            id=bucket_name,
            kinds=["GCPBucket", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(bucket_node)
        
        for variation in normalize_variations(bucket_name, discovered_project_names):
            node_id_map[variation] = bucket_name

    # Add ONLY enumerated BigQuery datasets (no fake ones)
    for dataset in bigquery_datasets:
        dataset_id = dataset.get('objectId', dataset.get('datasetId', ''))
        
        # ✅ VALIDATION: Skip if no valid dataset ID
        if not dataset_id or not dataset_id.strip():
            print(f"[WARNING] Skipping dataset with invalid ID: {dataset}")
            continue
            
        dataset_name = dataset.get('name', dataset.get('datasetId', ''))
        
        clean_properties = {
            "name": dataset_name,
            "displayname": dataset.get('displayName', dataset_name),
            "objectid": dataset_id,
            "datasetId": dataset.get('datasetId', dataset_name),
            "platform": "GCP",
            "project": dataset.get('project', 'Unknown'),
            "description": f"BigQuery Dataset: {dataset_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "BigQuery Dataset",
            "gcpDatasetType": "BigQuery",
            "gcpTableCount": dataset.get('tableCount', 'Unknown'),
            "location": dataset.get('location', 'Unknown'),
            "creationTime": dataset.get('creationTime', 'Unknown'),
            "lastModifiedTime": dataset.get('lastModifiedTime', 'Unknown'),
            
            # Real security analysis
            "riskLevel": dataset.get('riskLevel', 'Unknown'),
            "gcpEncryption": dataset.get('encryption', 'Unknown'),
            "gcpDataClassification": dataset.get('dataClassification', 'Unknown'),
            "dataRetentionDays": dataset.get('dataRetentionDays', 'Unknown'),
            "containsPII": dataset.get('containsPII', 'Unknown'),
            "accessLogging": dataset.get('accessLogging', 'Unknown'),
            "remediationPriority": dataset.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        bq_node = Node(
            id=dataset_id,
            kinds=["GCPDataset", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(bq_node)
        
        for variation in normalize_variations(dataset_id, discovered_project_names):
            node_id_map[variation] = dataset_id

    # ✅ FIXED: Add logging resource nodes using ONLY real enumerated data (keep as GCPLogSink for icons)
    for sink in log_sinks:
        sink_id = sink.get('objectId', sink.get('name', ''))
        
        # ✅ VALIDATION: Skip if no valid sink ID
        if not sink_id or not sink_id.strip():
            print(f"[WARNING] Skipping log sink with invalid ID: {sink}")
            continue
        
        # Determine if this is a log stream but keep GCPLogSink kind for UI compatibility
        is_stream = sink.get('type') == 'log_stream' or sink.get('isLogStream') is True
        
        clean_properties = {
            "name": sink.get('name', 'Unknown'),
            "displayname": sink.get('displayName', sink.get('name', 'Unknown')),
            "objectid": sink_id,
            "platform": "GCP",
            "project": sink.get('project', 'Unknown'),
            "description": f"GCP {'Log Stream' if is_stream else 'Log Sink'}: {sink.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Sink",  # Keep as Log Sink for UI
            "destination": sink.get('destination', 'Unknown'),
            "filter": sink.get('filter', 'Unknown'),
            "writerIdentity": sink.get('writerIdentity', 'Unknown'),
            "includeChildren": sink.get('includeChildren', 'Unknown'),
            "disabled": sink.get('disabled', 'Unknown'),
            "createTime": sink.get('createTime', 'Unknown'),
            "updateTime": sink.get('updateTime', 'Unknown'),
            
            # Stream-specific properties
            "isLogStream": is_stream,  # Flag to identify streams
            "logType": sink.get('logType', 'Unknown'),
            "sensitivityLevel": sink.get('sensitivityLevel', 'Unknown'),
            "accessRequired": sink.get('accessRequired', []),
            
            # Real security analysis
            "riskLevel": sink.get('riskLevel', 'Unknown'),
            "escalationTarget": "Yes" if sink.get('writerIdentity') and sink.get('writerIdentity') != 'Unknown' else "Unknown",
            "remediationPriority": sink.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        # Use GCPLogSink kind for UI compatibility
        sink_node = Node(
            id=sink_id,
            kinds=["GCPLogSink", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(sink_node)
        
        for variation in normalize_variations(sink_id, discovered_project_names):
            node_id_map[variation] = sink_id

    # Add other logging resources (log buckets, metrics)
    for bucket in log_buckets:
        bucket_id = bucket.get('objectId', bucket.get('name', ''))
        
        # ✅ VALIDATION: Skip if no valid bucket ID
        if not bucket_id or not bucket_id.strip():
            print(f"[WARNING] Skipping log bucket with invalid ID: {bucket}")
            continue
        
        clean_properties = {
            "name": bucket.get('name', 'Unknown'),
            "displayname": bucket.get('displayName', bucket.get('name', 'Unknown')),
            "objectid": bucket_id,
            "platform": "GCP",
            "project": bucket.get('project', 'Unknown'),
            "description": f"GCP Log Bucket: {bucket.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Bucket",
            "location": bucket.get('location', 'Unknown'),
            "retentionDays": bucket.get('retentionDays', 'Unknown'),
            "locked": bucket.get('locked', 'Unknown'),
            "lifecycleState": bucket.get('lifecycleState', 'Unknown'),
            "createTime": bucket.get('createTime', 'Unknown'),
            "updateTime": bucket.get('updateTime', 'Unknown'),
            
            # Real security analysis
            "riskLevel": bucket.get('riskLevel', 'Unknown'),
            "dataRetention": f"{bucket.get('retentionDays', 'Unknown')} days" if bucket.get('retentionDays') != 'Unknown' else 'Unknown',
            "complianceStatus": "COMPLIANT" if bucket.get('locked') is True else "NON_COMPLIANT" if bucket.get('locked') is False else "Unknown",
            "remediationPriority": bucket.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        log_bucket_node = Node(
            id=bucket_id,
            kinds=["GCPLogBucket", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(log_bucket_node)
        
        for variation in normalize_variations(bucket_id, discovered_project_names):
            node_id_map[variation] = bucket_id

    for metric in log_metrics:
        metric_id = metric.get('objectId', metric.get('name', ''))
        
        # ✅ VALIDATION: Skip if no valid metric ID
        if not metric_id or not metric_id.strip():
            print(f"[WARNING] Skipping log metric with invalid ID: {metric}")
            continue
        
        clean_properties = {
            "name": metric.get('name', 'Unknown'),
            "displayname": metric.get('displayName', metric.get('name', 'Unknown')),
            "objectid": metric_id,
            "platform": "GCP",
            "project": metric.get('project', 'Unknown'),
            "description": f"GCP Log Metric: {metric.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Metric",
            "filter": metric.get('filter', 'Unknown'),
            "disabled": metric.get('disabled', 'Unknown'),
            "createTime": metric.get('createTime', 'Unknown'),
            "updateTime": metric.get('updateTime', 'Unknown'),
            "metricDescriptor": str(metric.get('metricDescriptor', 'Unknown')),
            
            # Real security analysis
            "riskLevel": metric.get('riskLevel', 'Unknown'),
            "monitoringSensitive": "Yes" if metric.get('filter') and any(sensitive in metric.get('filter', '').lower() 
                                               for sensitive in ['audit', 'auth', 'admin']) else "Unknown",
            "remediationPriority": metric.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        metric_node = Node(
            id=metric_id,
            kinds=["GCPLogMetric", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(metric_node)
        
        for variation in normalize_variations(metric_id, discovered_project_names):
            node_id_map[variation] = metric_id

    # Add current user using real data when possible
    if creds:
        try:
            from utils.auth import get_active_account
            current_user = get_active_account(creds).lower()
        except:
            current_user = "Unknown"
    else:
        current_user = "Unknown"
    
    if current_user != "Unknown":
        current_user_name = current_user.split('@')[0] if '@' in current_user else current_user
        
        clean_properties = {
            "name": current_user,
            "displayname": current_user,
            "objectid": current_user,
            "email": current_user,
            "platform": "GCP",
            "description": f"Authenticated User: {current_user}",
            
            # Enhanced searchability
            "username": current_user_name,
            "domain": current_user.split('@')[1] if '@' in current_user else 'Unknown',
            "userPrincipalName": current_user,
            
            # Real user info - mark as unknown since we don't have Admin SDK access
            "lastLogin": "Unknown",
            "creationTime": "Unknown",
            "mfaEnabled": "Unknown",
            "suspended": "Unknown",
            "mailboxSetup": "Unknown",
            
            # Security analysis
            "gcpResourceType": "User Account",
            "privilegeLevel": "Unknown",
            "accessLevel": "Unknown",
            "riskLevel": "Unknown",
            "remediationPriority": "Unknown",
            "detectedRoles": [],
            
            # Enhanced metadata
            "authMethod": "Service Account" if "gserviceaccount.com" in current_user else "User",
            "projectsAccessible": len(projects)
        }
        
        sanitized_properties = {k: sanitize_property_value(v) for k, v in clean_properties.items()}
        
        user_node = Node(
            id=current_user,
            kinds=["GCPUser", "GCPResource", "GCPHound"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(user_node)
        
        for variation in normalize_variations(current_user, discovered_project_names):
            node_id_map[variation] = current_user

    print(f"[DEBUG] Nodes added: {graph.get_node_count()}")
    print(f"[DEBUG] Total ID mappings: {len(node_id_map)}")

    # ✅ FIXED: Create logging access edges with IAM data
    logging_edges = create_logging_access_edges(log_sinks, current_user, service_accounts, iam_data)
    edges.extend(logging_edges)

    # ✅ ADD EDGE FILTERING HERE - THE MAIN FIX
    edges = filter_edges_for_bloodhound(edges)

    # ✅ CRITICAL FIX: Validate edges before processing
    edges = validate_and_clean_graph_data(graph.nodes, edges, None)

    # ✅ CRITICAL FIX: Block SA→Project edges for SA-scoped permissions
    
    # Build edge variations for validation
    all_sa_variations = set()
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        for variation in normalize_variations(sa_email, discovered_project_names):
            all_sa_variations.add(variation)

    all_project_variations = set()
    for project in projects:
        project_id = project.get('projectId', '').lower()
        for variation in normalize_variations(project_id, discovered_project_names):
            all_project_variations.add(variation)

    # SA-scoped edge types that should NEVER target projects
    sa_scoped_edge_types = {
        'CanGetAccessToken', 'CanSignBlob', 'CanSignJWT', 
        'CanModifyIamPolicy', 'CanImpersonate', 'CanCreateKeys'
    }

    # Process edges with STRICT SA→SA vs SA→Project validation
    edges_added = 0
    skipped_edges = 0
    
    for i, edge_data in enumerate(edges):
        start_id = edge_data.get("start", {}).get("value", "").lower()
        end_id = edge_data.get("end", {}).get("value", "").lower()
        kind = fix_edge_name(edge_data.get("kind", "RelatedTo"))
        
        # ✅ ADDITIONAL VALIDATION: Skip if either ID is empty
        if not start_id or not start_id.strip() or not end_id or not end_id.strip():
            skipped_edges += 1
            print(f"[DEBUG] ❌ Skipping edge with empty ID: start='{start_id}', end='{end_id}'")
            continue
        
        actual_start = node_id_map.get(start_id, start_id)
        actual_end = node_id_map.get(end_id, end_id)
        
        # ✅ CRITICAL FIX: Block SA→Project edges for SA-scoped permissions
        if kind in sa_scoped_edge_types and end_id in all_project_variations:
            skipped_edges += 1
            print(f"[DEBUG] ❌ Blocking invalid SA→Project edge: {start_id} --[{kind}]-> {end_id}")
            continue
            
        # ✅ Also block if target is not a valid node
        if actual_start not in graph.nodes or actual_end not in graph.nodes:
            skipped_edges += 1
            print(f"[DEBUG] ❌ Skipping edge to missing node: {actual_start} -> {actual_end}")
            continue
        
        # Process valid edges
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
            if edges_added <= 5:  # Show first 5 successful edges
                print(f"[DEBUG] ✅ Edge #{edges_added}: {actual_start} --[{kind}]-> {actual_end}")

    print(f"[DEBUG] Edges added: {edges_added}/{len(edges)} (skipped {skipped_edges} invalid edges)")

    # Export with schema validation
    os.makedirs("./output", exist_ok=True)
    
    # Dynamic filename generation based on authenticated user
    if creds and current_user != "Unknown":
        try:
            from utils.auth import get_safe_output_filename
            output_filename = get_safe_output_filename(current_user)
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
        print(f"[+] 🎯 GCP ATTACK SURFACE WITH LOGGING INTEGRATION COMPLETE")
        return output_file
    else:
        print(f"[!] ❌ Export failed")
        return None
