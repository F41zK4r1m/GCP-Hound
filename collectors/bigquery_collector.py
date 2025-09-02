from google.cloud import bigquery
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

def collect_bigquery_resources(creds, projects):
    """
    Enumerate all BigQuery datasets and tables across accessible projects.
    Returns a list of dataset dicts with security analysis.
    """
    datasets = []
    
    print(f"\n{colorize('[*] ENUMERATING BIGQUERY DATASETS AND TABLES...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Create BigQuery client for this project
            client = bigquery.Client(project=project_id, credentials=creds)
            
            # List datasets in this project
            project_datasets = list(client.list_datasets())
            
            if not project_datasets:
                print(f"[~] No BigQuery datasets found in {project_id}")
                continue
            
            for dataset_ref in project_datasets:
                try:
                    # Get detailed dataset information
                    dataset = client.get_dataset(dataset_ref.dataset_id)
                    
                    # Analyze dataset access permissions
                    access_entries = []
                    for access_entry in dataset.access_entries:
                        access_entries.append({
                            'entity_type': access_entry.entity_type,
                            'entity_id': access_entry.entity_id,
                            'role': access_entry.role
                        })
                    
                    # Get tables in this dataset
                    tables = []
                    try:
                        dataset_tables = list(client.list_tables(dataset.dataset_id))
                        for table_ref in dataset_tables:
                            try:
                                table = client.get_table(table_ref)
                                tables.append({
                                    'table_id': table.table_id,
                                    'full_table_id': table.full_table_id,
                                    'table_type': table.table_type,
                                    'num_rows': table.num_rows,
                                    'num_bytes': table.num_bytes,
                                    'created': table.created.isoformat() if table.created else None,
                                    'modified': table.modified.isoformat() if table.modified else None,
                                    'description': table.description,
                                    'schema': [{'name': field.name, 'type': field.field_type, 'mode': field.mode} 
                                             for field in table.schema] if table.schema else []
                                })
                            except Exception as e:
                                # Continue if we can't access individual table details
                                tables.append({
                                    'table_id': table_ref.table_id,
                                    'access_error': str(e)
                                })
                    except Exception as e:
                        print(f"    {colorize('!', TerminalColors.YELLOW)} Cannot list tables in {dataset.dataset_id}: {e}")
                    
                    # Build comprehensive dataset info
                    dataset_info = {
                        'dataset_id': dataset.dataset_id,
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
                        'riskLevel': 'UNKNOWN'
                    }
                    
                    # Assess security risk level
                    dataset_info = _assess_dataset_risk(dataset_info)
                    
                    datasets.append(dataset_info)
                    
                    # Print discovery with risk assessment
                    risk_color = TerminalColors.RED if dataset_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if dataset_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                    table_info = f"{len(tables)} tables" if tables else "no tables"
                    print(f"    {colorize('📊', risk_color)} {dataset.full_dataset_id} ({table_info}) - {colorize(dataset_info['riskLevel'] + ' RISK', risk_color)}")
                    
                except Exception as e:
                    print(f"    {colorize('!', TerminalColors.YELLOW)} Error accessing dataset {dataset_ref.dataset_id}: {e}")
            
            if project_datasets:
                high_risk = len([d for d in datasets if d.get('project') == project_id and d['riskLevel'] == 'HIGH'])
                medium_risk = len([d for d in datasets if d.get('project') == project_id and d['riskLevel'] == 'MEDIUM'])
                total_in_project = len([d for d in datasets if d.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} datasets in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk datasets")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk datasets")
                
        except Exception as e:
            error_msg = str(e)
            if "BigQuery API has not been used" in error_msg:
                print(f"[!] BigQuery API not enabled for project {project_id}")
            elif "403" in error_msg:
                print(f"[!] No BigQuery access for project {project_id}")
            else:
                print(f"[!] Error accessing BigQuery in {project_id}: {e}")
    
    # Final summary
    total_datasets = len(datasets)
    high_risk_datasets = len([d for d in datasets if d['riskLevel'] == 'HIGH'])
    medium_risk_datasets = len([d for d in datasets if d['riskLevel'] == 'MEDIUM'])
    total_tables = sum(d['table_count'] for d in datasets)
    
    print(f"\n{colorize('[+] BIGQUERY ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('📊 Total Datasets Discovered:', TerminalColors.BLUE)} {colorize(str(total_datasets), TerminalColors.WHITE)}")
    print(f"    {colorize('📋 Total Tables Discovered:', TerminalColors.BLUE)} {colorize(str(total_tables), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH-Risk Datasets:', TerminalColors.RED)} {colorize(str(high_risk_datasets), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM-Risk Datasets:', TerminalColors.YELLOW)} {colorize(str(medium_risk_datasets), TerminalColors.WHITE)}")
    
    return datasets

def _assess_dataset_risk(dataset_info):
    """Assess security risk level of a BigQuery dataset."""
    risk_factors = 0
    access_entries = dataset_info.get('access_entries', [])
    
    # High risk factors
    # Public access
    for entry in access_entries:
        if entry.get('entity_id') in ['allUsers', 'allAuthenticatedUsers']:
            risk_factors += 3  # Critical risk
        elif entry.get('entity_type') == 'domain':
            risk_factors += 1  # Domain-wide access
    
    # Many principals have access
    if len(access_entries) > 10:
        risk_factors += 2
    elif len(access_entries) > 5:
        risk_factors += 1
    
    # Large number of tables (valuable dataset)
    table_count = dataset_info.get('table_count', 0)
    if table_count > 50:
        risk_factors += 2
    elif table_count > 10:
        risk_factors += 1
    
    # Editor/Owner roles
    dangerous_roles = ['OWNER', 'EDITOR', 'roles/bigquery.admin']
    for entry in access_entries:
        if entry.get('role') in dangerous_roles:
            risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 4:
        dataset_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        dataset_info['riskLevel'] = 'MEDIUM'
    else:
        dataset_info['riskLevel'] = 'LOW'
    
    return dataset_info

def analyze_bigquery_access_privileges(creds, datasets, service_accounts):
    """
    Analyze which service accounts can access which BigQuery datasets.
    """
    access_analysis = []
    
    print(f"\n{colorize('[*] ANALYZING BIGQUERY ACCESS PRIVILEGES...', TerminalColors.CYAN)}")
    
    for dataset in datasets:
        dataset_id = dataset['dataset_id']
        project_id = dataset['project']
        full_dataset_id = dataset['full_dataset_id']
        
        dataset_access = {
            'dataset': full_dataset_id,
            'project': project_id,
            'canAccessDataset': [],
            'escalationRisk': 'LOW'
        }
        
        # Check explicit access entries
        for access_entry in dataset.get('access_entries', []):
            entity_type = access_entry.get('entity_type')
            entity_id = access_entry.get('entity_id')
            role = access_entry.get('role')
            
            if entity_type == 'userByEmail':
                # Check if this matches any of our service accounts
                matching_sa = next((sa for sa in service_accounts 
                                  if sa.get('email') == entity_id), None)
                if matching_sa:
                    dataset_access['canAccessDataset'].append({
                        'serviceAccount': entity_id,
                        'role': role,
                        'displayName': matching_sa.get('displayName', entity_id)
                    })
                    print(f"    {colorize('🔑', TerminalColors.YELLOW)} {matching_sa.get('displayName', entity_id)}: Can access dataset {colorize(full_dataset_id, TerminalColors.WHITE)} as {role}")
        
        # Test BigQuery permissions for service accounts
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            can_access = _test_bigquery_dataset_access(creds, project_id, dataset_id, sa_email)
            
            if can_access and not any(access['serviceAccount'] == sa_email 
                                    for access in dataset_access['canAccessDataset']):
                dataset_access['canAccessDataset'].append({
                    'serviceAccount': sa_email,
                    'role': 'inherited',
                    'displayName': sa.get('displayName', sa_email)
                })
                print(f"    {colorize('🔓', TerminalColors.CYAN)} {sa.get('displayName', sa_email)}: Has inherited access to {colorize(full_dataset_id, TerminalColors.WHITE)}")
        
        # Assess escalation risk
        if len(dataset_access['canAccessDataset']) > 3:
            dataset_access['escalationRisk'] = 'HIGH'
        elif len(dataset_access['canAccessDataset']) > 0:
            dataset_access['escalationRisk'] = 'MEDIUM'
        
        access_analysis.append(dataset_access)
    
    # Summary
    high_risk_datasets = len([d for d in access_analysis if d['escalationRisk'] == 'HIGH'])
    medium_risk_datasets = len([d for d in access_analysis if d['escalationRisk'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] BIGQUERY ACCESS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('🚨 HIGH Risk Dataset Access:', TerminalColors.RED)} {colorize(str(high_risk_datasets), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM Risk Dataset Access:', TerminalColors.YELLOW)} {colorize(str(medium_risk_datasets), TerminalColors.WHITE)}")
    
    return access_analysis

def _test_bigquery_dataset_access(creds, project_id, dataset_id, service_account_email):
    """Test if a service account can access a specific BigQuery dataset."""
    try:
        # Use IAM API to test BigQuery permissions
        iam = build("iam", "v1", credentials=creds)
        
        # Test dataset access permission
        test_request = iam.projects().serviceAccounts().testIamPermissions(
            resource=f"projects/{project_id}/serviceAccounts/{service_account_email}",
            body={'permissions': [
                'bigquery.datasets.get',
                'bigquery.tables.list',
                'bigquery.tables.get'
            ]}
        )
        test_response = test_request.execute()
        
        granted_permissions = test_response.get('permissions', [])
        return len(granted_permissions) > 0
        
    except Exception:
        return False

def build_bigquery_edges(datasets, dataset_access_analysis, current_user):
    """
    Build BloodHound edges for BigQuery dataset relationships and access patterns.
    """
    edges = []
    
    for dataset in datasets:
        dataset_id = dataset['dataset_id']
        project_id = dataset['project']
        full_dataset_id = dataset['full_dataset_id']
        bq_dataset_id = f"gcp-bq-dataset-{project_id}-{dataset_id}"
        
        # Edge: Dataset belongs to project
        edges.append({
            "start": {"value": bq_dataset_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "bigquery_enumeration",
                "datasetId": dataset_id,
                "fullDatasetId": full_dataset_id,
                "tableCount": dataset['table_count'],
                "riskLevel": dataset['riskLevel'],
                "location": dataset.get('location', 'unknown')
            }
        })
        
        # Edges for tables within dataset
        for table in dataset.get('tables', []):
            if 'access_error' in table:
                continue
                
            table_id = table['table_id']
            bq_table_id = f"gcp-bq-table-{project_id}-{dataset_id}-{table_id}"
            
            # Edge: Table belongs to dataset
            edges.append({
                "start": {"value": bq_table_id},
                "end": {"value": bq_dataset_id},
                "kind": "BelongsTo",
                "properties": {
                    "source": "bigquery_enumeration",
                    "tableId": table_id,
                    "tableType": table.get('table_type', 'unknown'),
                    "numRows": table.get('num_rows'),
                    "numBytes": table.get('num_bytes')
                }
            })
    
    # Edges for service account access to datasets
    for analysis in dataset_access_analysis:
        dataset_parts = analysis['dataset'].split(':')
        if len(dataset_parts) == 2:
            project_id, dataset_id = dataset_parts
            bq_dataset_id = f"gcp-bq-dataset-{project_id}-{dataset_id}"
            
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
                        "riskLevel": analysis['escalationRisk'],
                        "description": f"Service account can access BigQuery dataset {analysis['dataset']}",
                        "escalationMethod": "bigquery_data_access"
                    }
                })
    
    return edges
