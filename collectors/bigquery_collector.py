from google.cloud import bigquery
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.id_utils import normalize_dataset_id, normalize_all_dataset_variations

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

def collect_paginated_datasets(bigquery_client):
    """
    Helper function to collect all paginated datasets from a BigQuery client.
    """
    all_datasets = []
    page_count = 0
    
    try:
        # Use pagination to get ALL datasets
        dataset_iterator = bigquery_client.list_datasets()
        
        for page in dataset_iterator.pages:
            page_count += 1
            datasets_in_page = list(page)
            all_datasets.extend(datasets_in_page)
            
    except Exception as e:
        print(f"[!] Error during dataset pagination: {e}")
        
    return all_datasets, page_count

def collect_paginated_tables(bigquery_client, dataset_id):
    """
    Helper function to collect all paginated tables from a BigQuery dataset.
    
    Args:
        bigquery_client: BigQuery client instance
        dataset_id: Raw dataset ID to list tables from
    
    Returns:
        Tuple of (all_tables_list, page_count)
    """
    all_tables = []
    page_count = 0
    
    try:
        # Use pagination to get ALL tables in dataset
        table_iterator = bigquery_client.list_tables(dataset_id)
        
        for page in table_iterator.pages:
            page_count += 1
            tables_in_page = list(page)
            all_tables.extend(tables_in_page)
            
    except Exception as e:
        print(f"[!] Error during table pagination for dataset {dataset_id}: {e}")
        
    return all_tables, page_count

def collect_bigquery_resources(creds, projects):
    """
    Enumerate all BigQuery datasets and tables across accessible projects with pagination support.
    Returns a list of dataset dicts with comprehensive security analysis.
    """
    datasets = []
    total_projects_processed = 0
    total_datasets_found = 0
    total_tables_found = 0

    print(f"\n{colorize('[*] ENUMERATING BIGQUERY DATASETS AND TABLES...', TerminalColors.CYAN)}")

    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        total_projects_processed += 1

        try:
            # Create BigQuery client for this project
            client = bigquery.Client(project=project_id, credentials=creds)

            # Use pagination to get ALL datasets
            project_datasets, dataset_pages = collect_paginated_datasets(client)
            
            if not project_datasets:
                print(f"[~] No BigQuery datasets found in {project_id}")
                continue

            project_dataset_count = 0
            project_table_count = 0

            for dataset_ref in project_datasets:
                try:
                    raw_dataset_id = dataset_ref.dataset_id
                    dataset = client.get_dataset(raw_dataset_id)
                    norm_dataset_id = normalize_dataset_id(raw_dataset_id, project_id)

                    # Analyze dataset access permissions with enhanced structure
                    access_entries = []
                    for access_entry in dataset.access_entries:
                        access_entries.append({
                            'entity_type': access_entry.entity_type,
                            'entity_id': access_entry.entity_id,
                            'role': access_entry.role
                        })

                    # Use pagination to get ALL tables in this dataset
                    tables = []
                    try:
                        dataset_tables, table_pages = collect_paginated_tables(client, raw_dataset_id)
                        
                        for table_ref in dataset_tables:
                            try:
                                table = client.get_table(table_ref)
                                table_info = {
                                    'table_id': table.table_id,
                                    'full_table_id': table.full_table_id,
                                    'table_type': table.table_type,
                                    'num_rows': table.num_rows,
                                    'num_bytes': table.num_bytes,
                                    'created': table.created.isoformat() if table.created else None,
                                    'modified': table.modified.isoformat() if table.modified else None,
                                    'description': table.description,
                                    'schema': [{'name': field.name, 'type': field.field_type, 'mode': field.mode}
                                               for field in table.schema] if table.schema else [],
                                    # Enhanced table metadata
                                    'clustering_fields': table.clustering_fields,
                                    'time_partitioning': {
                                        'type': table.time_partitioning.type_ if table.time_partitioning else None,
                                        'field': table.time_partitioning.field if table.time_partitioning else None
                                    },
                                    'encryption_configuration': {
                                        'kms_key_name': table.encryption_configuration.kms_key_name if table.encryption_configuration else None
                                    }
                                }
                                tables.append(table_info)
                                
                            except Exception as e:
                                tables.append({
                                    'table_id': table_ref.table_id,
                                    'access_error': str(e)
                                })
                                
                    except Exception as e:
                        print(f" {colorize('!', TerminalColors.YELLOW)} Cannot list tables in {norm_dataset_id}: {e}")

                    # Build comprehensive dataset info with enhanced metadata
                    dataset_info = {
                        'dataset_id': norm_dataset_id,
                        'raw_dataset_id': raw_dataset_id,
                        'full_dataset_id': dataset.full_dataset_id,
                        'project': project_id,
                        'projectName': project.get('name', project_id),
                        'friendly_name': dataset.friendly_name,
                        'description': dataset.description,
                        'location': dataset.location,
                        'created': dataset.created.isoformat() if dataset.created else None,
                        'modified': dataset.modified.isoformat() if dataset.modified else None,
                        'labels': dict(dataset.labels) if dataset.labels else {},
                        'access_entries': access_entries,
                        'tables': tables,
                        'table_count': len(tables),
                        # Enhanced dataset metadata
                        'default_table_expiration': dataset.default_table_expiration_ms,
                        'default_partition_expiration': dataset.default_partition_expiration_ms,
                        'etag': dataset.etag,
                        'riskLevel': 'UNKNOWN'
                    }

                    # Assess security risk level with enhanced analysis
                    dataset_info = assess_dataset_risk_enhanced(dataset_info)
                    datasets.append(dataset_info)
                    
                    project_dataset_count += 1
                    project_table_count += len(tables)

                    # Print discovery with enhanced risk assessment
                    risk_color = TerminalColors.RED if dataset_info['riskLevel'] == 'HIGH' else \
                                 TerminalColors.YELLOW if dataset_info['riskLevel'] == 'MEDIUM' else \
                                 TerminalColors.GREEN
                    table_info_str = f"{len(tables)} tables" if tables else "no tables"
                    print(f" {colorize('📊', risk_color)} {norm_dataset_id} ({table_info_str}) - {colorize(dataset_info['riskLevel'] + ' RISK', risk_color)}")

                except Exception as e:
                    norm_dataset_id = normalize_dataset_id(dataset_ref.dataset_id, project_id)
                    print(f" {colorize('!', TerminalColors.YELLOW)} Error accessing dataset {norm_dataset_id}: {e}")

            # Enhanced project summary with pagination info
            if project_datasets:
                high_risk = len([d for d in datasets if d.get('project') == project_id and d['riskLevel'] == 'HIGH'])
                medium_risk = len([d for d in datasets if d.get('project') == project_id and d['riskLevel'] == 'MEDIUM'])
                
                print(f"[+] Found {colorize(str(project_dataset_count), TerminalColors.WHITE)} datasets with {colorize(str(project_table_count), TerminalColors.WHITE)} tables in {colorize(project_id, TerminalColors.CYAN)}")
                
                if high_risk > 0:
                    print(f" {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk datasets")
                if medium_risk > 0:
                    print(f" {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk datasets")
                    
            total_datasets_found += project_dataset_count
            total_tables_found += project_table_count

        except Exception as e:
            error_msg = str(e)
            if "BigQuery API has not been used" in error_msg:
                print(f"[!] BigQuery API not enabled for project {project_id}")
            elif "403" in error_msg:
                print(f"[!] No BigQuery access for project {project_id}")
            else:
                print(f"[!] Error accessing BigQuery in {project_id}: {e}")

    # Enhanced final summary
    high_risk_datasets = len([d for d in datasets if d['riskLevel'] == 'HIGH'])
    medium_risk_datasets = len([d for d in datasets if d['riskLevel'] == 'MEDIUM'])

    print(f"\n{colorize('[+] BIGQUERY ENUMERATION SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f" {colorize('📊 Total Datasets:', TerminalColors.BLUE)} {colorize(str(total_datasets_found), TerminalColors.WHITE)}")
    print(f" {colorize('📋 Total Tables:', TerminalColors.BLUE)} {colorize(str(total_tables_found), TerminalColors.WHITE)}")
    print(f" {colorize('🚨 HIGH-Risk Datasets:', TerminalColors.RED)} {colorize(str(high_risk_datasets), TerminalColors.WHITE)}")
    print(f" {colorize('⚠ MEDIUM-Risk Datasets:', TerminalColors.YELLOW)} {colorize(str(medium_risk_datasets), TerminalColors.WHITE)}")
    print(f" {colorize('🏗 Projects Processed:', TerminalColors.BLUE)} {colorize(str(total_projects_processed), TerminalColors.WHITE)}\n")

    return datasets

def assess_dataset_risk_enhanced(dataset_info):
    """
    Enhanced security risk assessment for BigQuery datasets with comprehensive analysis.
    
    Args:
        dataset_info: Dataset information dictionary
    
    Returns:
        Updated dataset_info with riskLevel set
    """
    risk_factors = 0
    access_entries = dataset_info.get('access_entries', [])

    # Critical risk factors
    for entry in access_entries:
        entity_id = entry.get('entity_id', '')
        entity_type = entry.get('entity_type', '')
        role = entry.get('role', '')
        
        # Public access - critical risk
        if entity_id in ['allUsers', 'allAuthenticatedUsers']:
            risk_factors += 4  # Critical risk
        # Domain-wide access
        elif entity_type == 'domain':
            risk_factors += 2  # High risk
        # Administrative roles
        elif role in ['OWNER', 'EDITOR', 'roles/bigquery.admin']:
            risk_factors += 1

    # Access control complexity
    if len(access_entries) > 15:
        risk_factors += 2
    elif len(access_entries) > 10:
        risk_factors += 1

    # Dataset size and complexity
    table_count = dataset_info.get('table_count', 0)
    if table_count > 100:
        risk_factors += 2
    elif table_count > 50:
        risk_factors += 1

    # Data retention and lifecycle risks
    if not dataset_info.get('default_table_expiration'):
        risk_factors += 1  # No automatic cleanup

    # Encryption analysis
    tables_without_encryption = 0
    for table in dataset_info.get('tables', []):
        if not table.get('encryption_configuration', {}).get('kms_key_name'):
            tables_without_encryption += 1
    
    if tables_without_encryption > 0 and table_count > 0:
        encryption_ratio = tables_without_encryption / table_count
        if encryption_ratio > 0.5:  # More than 50% unencrypted
            risk_factors += 1

    # Final risk assessment
    if risk_factors >= 5:
        dataset_info['riskLevel'] = 'CRITICAL'
    elif risk_factors >= 3:
        dataset_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 1:
        dataset_info['riskLevel'] = 'MEDIUM'
    else:
        dataset_info['riskLevel'] = 'LOW'

    return dataset_info

def analyze_bigquery_access_privileges(creds, datasets, service_accounts):
    """
    Analyze which service accounts can access which BigQuery datasets with enhanced analysis.
    """
    access_analysis = []
    total_access_relationships = 0

    print(f"\n{colorize('[*] ANALYZING BIGQUERY ACCESS PRIVILEGES...', TerminalColors.CYAN)}")

    for dataset in datasets:
        norm_dataset_id = dataset['dataset_id']
        project_id = dataset['project']
        full_dataset_id = dataset['full_dataset_id']

        dataset_access = {
            'dataset': full_dataset_id,
            'project': project_id,
            'canAccessDataset': [],
            'escalationRisk': 'LOW',
            'accessSummary': {
                'directAccess': 0,
                'inheritedAccess': 0,
                'adminAccess': 0
            }
        }

        # Analyze explicit access entries
        for access_entry in dataset.get('access_entries', []):
            entity_type = access_entry.get('entity_type')
            entity_id = access_entry.get('entity_id')
            role = access_entry.get('role')

            if entity_type == 'userByEmail':
                matching_sa = next((sa for sa in service_accounts if sa.get('email') == entity_id), None)
                if matching_sa:
                    access_info = {
                        'serviceAccount': entity_id,
                        'role': role,
                        'displayName': matching_sa.get('displayName', entity_id),
                        'accessType': 'direct'
                    }
                    dataset_access['canAccessDataset'].append(access_info)
                    dataset_access['accessSummary']['directAccess'] += 1
                    
                    if role in ['OWNER', 'EDITOR', 'roles/bigquery.admin']:
                        dataset_access['accessSummary']['adminAccess'] += 1
                    
                    print(f" {colorize('🔑', TerminalColors.YELLOW)} {matching_sa.get('displayName', entity_id)}: Direct access to {colorize(full_dataset_id, TerminalColors.WHITE)} as {role}")

        # Test inherited access for project service accounts
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue

            sa_email = sa.get('email')
            # Skip if already has direct access
            if any(access['serviceAccount'] == sa_email for access in dataset_access['canAccessDataset']):
                continue
                
            can_access = test_bigquery_dataset_access_enhanced(creds, project_id, norm_dataset_id, sa_email)
            
            if can_access:
                access_info = {
                    'serviceAccount': sa_email,
                    'role': 'inherited',
                    'displayName': sa.get('displayName', sa_email),
                    'accessType': 'inherited'
                }
                dataset_access['canAccessDataset'].append(access_info)
                dataset_access['accessSummary']['inheritedAccess'] += 1
                
                print(f" {colorize('🔓', TerminalColors.CYAN)} {sa.get('displayName', sa_email)}: Inherited access to {colorize(full_dataset_id, TerminalColors.WHITE)}")

        # Enhanced risk assessment
        total_access = len(dataset_access['canAccessDataset'])
        admin_access = dataset_access['accessSummary']['adminAccess']
        
        if admin_access > 2 or total_access > 5:
            dataset_access['escalationRisk'] = 'HIGH'
        elif admin_access > 0 or total_access > 2:
            dataset_access['escalationRisk'] = 'MEDIUM'
        elif total_access > 0:
            dataset_access['escalationRisk'] = 'LOW'

        access_analysis.append(dataset_access)
        total_access_relationships += total_access

    # Enhanced summary
    high_risk_datasets = len([d for d in access_analysis if d['escalationRisk'] == 'HIGH'])
    medium_risk_datasets = len([d for d in access_analysis if d['escalationRisk'] == 'MEDIUM'])

    print(f"\n{colorize('[+] BIGQUERY ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f" {colorize('🚨 HIGH Risk Dataset Access:', TerminalColors.RED)} {colorize(str(high_risk_datasets), TerminalColors.WHITE)}")
    print(f" {colorize('⚠ MEDIUM Risk Dataset Access:', TerminalColors.YELLOW)} {colorize(str(medium_risk_datasets), TerminalColors.WHITE)}")
    print(f" {colorize('🔗 Total Access Relationships:', TerminalColors.BLUE)} {colorize(str(total_access_relationships), TerminalColors.WHITE)}\n")

    return access_analysis

def test_bigquery_dataset_access_enhanced(creds, project_id, normalized_dataset_id, service_account_email):
    """Enhanced test for BigQuery dataset access permissions"""
    try:
        iam = build("iam", "v1", credentials=creds)
        test_request = iam.projects().serviceAccounts().testIamPermissions(
            resource=f"projects/{project_id}/serviceAccounts/{service_account_email}",
            body={'permissions': [
                'bigquery.datasets.get',
                'bigquery.tables.list',
                'bigquery.tables.get',
                'bigquery.tables.getData'  # Enhanced permission check
            ]}
        )
        test_response = test_request.execute()
        granted_permissions = test_response.get('permissions', [])
        return len(granted_permissions) >= 2  # Need at least dataset and table access
    except Exception:
        return False

def build_bigquery_edges(datasets, dataset_access_analysis, current_user):
    """
    Build comprehensive BloodHound edges for BigQuery relationships with enhanced metadata.
    """
    edges = []

    for dataset in datasets:
        norm_dataset_id = dataset['dataset_id']
        project_id = dataset['project']
        full_dataset_id = dataset['full_dataset_id']
        bq_dataset_id = norm_dataset_id

        # Enhanced dataset → project edge
        edges.append({
            "start": {"value": bq_dataset_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "bigquery_enumeration",
                "datasetId": bq_dataset_id,
                "fullDatasetId": full_dataset_id,
                "tableCount": dataset['table_count'],
                "riskLevel": dataset['riskLevel'],
                "location": dataset.get('location', 'unknown'),
                "hasTableExpiration": bool(dataset.get('default_table_expiration')),
                "accessEntryCount": len(dataset.get('access_entries', []))
            }
        })

        # Enhanced table → dataset edges
        for table in dataset.get('tables', []):
            if 'access_error' in table:
                continue

            table_id = table['table_id']
            bq_table_id = f"gcp-bq-table-{project_id}-{norm_dataset_id}-{table_id}"

            edges.append({
                "start": {"value": bq_table_id},
                "end": {"value": bq_dataset_id},
                "kind": "BelongsTo",
                "properties": {
                    "source": "bigquery_enumeration",
                    "tableId": table_id,
                    "tableType": table.get('table_type', 'unknown'),
                    "numRows": table.get('num_rows'),
                    "numBytes": table.get('num_bytes'),
                    "isEncrypted": bool(table.get('encryption_configuration', {}).get('kms_key_name')),
                    "isPartitioned": bool(table.get('time_partitioning', {}).get('type')),
                    "isClustered": bool(table.get('clustering_fields'))
                }
            })

    # Enhanced service account access edges
    for analysis in dataset_access_analysis:
        dataset_id = analysis['dataset']
        norm_id = normalize_dataset_id(dataset_id.split(":")[-1], analysis['project'])
        bq_dataset_id = norm_id
        
        for access in analysis['canAccessDataset']:
            sa_email = access['serviceAccount']
            sa_id = sa_email.replace('@', '_').replace('.', '_')

            edges.append({
                "start": {"value": f"gcp-sa-{sa_id}"},
                "end": {"value": bq_dataset_id},
                "kind": "CanAccessBigQueryDataset",
                "properties": {
                    "source": "bigquery_access_analysis",
                    "role": access['role'],
                    "accessType": access['accessType'],
                    "riskLevel": analysis['escalationRisk'],
                    "description": f"Service account can access BigQuery dataset {dataset_id}",
                    "escalationMethod": "bigquery_data_access"
                }
            })

    return edges
