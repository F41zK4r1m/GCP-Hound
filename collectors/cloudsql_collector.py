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

def collect_cloudsql_instances(creds, projects):
    """
    Enumerate all Cloud SQL instances across accessible projects.
    Returns a list of instance dicts with security analysis.
    """
    instances = []
    
    print(f"\n{colorize('[*] ENUMERATING CLOUD SQL INSTANCES...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Cloud SQL Admin API client
            sqladmin = build("sqladmin", "v1", credentials=creds)
            
            # List SQL instances in this project
            request = sqladmin.instances().list(project=project_id)
            response = request.execute()
            project_instances = response.get('items', [])
            
            if not project_instances:
                print(f"[~] No Cloud SQL instances found in {project_id}")
                continue
            
            for instance in project_instances:
                # Enrich instance data with security analysis
                instance_info = {
                    'name': instance.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'databaseVersion': instance.get('databaseVersion'),
                    'state': instance.get('state'),
                    'connectionName': instance.get('connectionName'),
                    'ipAddresses': instance.get('ipAddresses', []),
                    'settings': instance.get('settings', {}),
                    'serverCaCert': instance.get('serverCaCert', {}),
                    'instanceType': instance.get('instanceType'),
                    'backendType': instance.get('backendType'),
                    'region': instance.get('region'),
                    'gceZone': instance.get('gceZone'),
                    'serviceAccountEmailAddress': instance.get('serviceAccountEmailAddress'),
                    'riskLevel': 'UNKNOWN'
                }
                
                # Assess security risk level
                instance_info = _assess_cloudsql_risk(instance_info)
                
                instances.append(instance_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if instance_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if instance_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                db_version = instance_info['databaseVersion']
                state = instance_info['state']
                print(f"    {colorize('🗄️', risk_color)} {instance_info['name']} ({db_version}, {state}) - {colorize(instance_info['riskLevel'] + ' RISK', risk_color)}")
            
            if project_instances:
                high_risk = len([i for i in instances if i.get('project') == project_id and i['riskLevel'] == 'HIGH'])
                medium_risk = len([i for i in instances if i.get('project') == project_id and i['riskLevel'] == 'MEDIUM'])
                total_in_project = len([i for i in instances if i.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} Cloud SQL instances in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk instances")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk instances")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Cloud SQL access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Cloud SQL API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Cloud SQL in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Cloud SQL in {project_id}: {e}")
    
    # Final summary
    total_instances = len(instances)
    high_risk_instances = len([i for i in instances if i['riskLevel'] == 'HIGH'])
    medium_risk_instances = len([i for i in instances if i['riskLevel'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] CLOUD SQL ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('🗄️ Total Instances Discovered:', TerminalColors.BLUE)} {colorize(str(total_instances), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH-Risk Instances:', TerminalColors.RED)} {colorize(str(high_risk_instances), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM-Risk Instances:', TerminalColors.YELLOW)} {colorize(str(medium_risk_instances), TerminalColors.WHITE)}")
    
    return instances

def _assess_cloudsql_risk(instance_info):
    """Assess security risk level of a Cloud SQL instance."""
    risk_factors = 0
    settings = instance_info.get('settings', {})
    ip_config = settings.get('ipConfiguration', {})
    
    # Public IP address
    if ip_config.get('ipv4Enabled', False):
        risk_factors += 2
    
    # No authorized networks (allows all IPs)
    authorized_networks = ip_config.get('authorizedNetworks', [])
    if len(authorized_networks) == 0 and ip_config.get('ipv4Enabled', False):
        risk_factors += 2
    
    # SSL not required
    if not ip_config.get('requireSsl', False):
        risk_factors += 1
    
    # Backup not enabled
    backup_config = settings.get('backupConfiguration', {})
    if not backup_config.get('enabled', False):
        risk_factors += 1
    
    # Binary logging disabled (for MySQL)
    if not backup_config.get('binaryLogEnabled', False):
        risk_factors += 1
    
    # Database flags that might be risky
    database_flags = settings.get('databaseFlags', [])
    risky_flags = ['skip_networking', 'local_infile']
    for flag in database_flags:
        if flag.get('name') in risky_flags and flag.get('value') == 'on':
            risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 4:
        instance_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        instance_info['riskLevel'] = 'MEDIUM'
    else:
        instance_info['riskLevel'] = 'LOW'
    
    return instance_info

def build_cloudsql_edges(instances, current_user):
    """Build BloodHound edges for Cloud SQL instances."""
    edges = []
    
    for instance in instances:
        instance_name = instance['name']
        project_id = instance['project']
        instance_id = f"gcp-cloudsql-{project_id}-{instance_name}"
        
        # Edge: Instance belongs to project
        edges.append({
            "start": {"value": instance_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "cloudsql_enumeration",
                "instanceName": instance_name,
                "databaseVersion": instance['databaseVersion'],
                "state": instance['state'],
                "riskLevel": instance['riskLevel']
            }
        })
        
        # Edge for high-risk instances
        if instance['riskLevel'] in ['HIGH', 'MEDIUM']:
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": instance_id},
                "kind": "CanAccessCloudSQL",
                "properties": {
                    "source": "cloudsql_enumeration",
                    "riskLevel": instance['riskLevel'],
                    "description": f"Potential access to Cloud SQL instance {instance_name}",
                    "escalationMethod": "database_access"
                }
            })
    
    return edges
