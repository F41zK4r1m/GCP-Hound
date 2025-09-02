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

def collect_compute_instances(creds, projects):
    """
    Enumerate all Compute Engine instances across accessible projects.
    Returns a list of instance dicts with security analysis.
    """
    instances = []
    
    print(f"\n{colorize('[*] ENUMERATING COMPUTE ENGINE INSTANCES...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Compute Engine API client
            compute = build("compute", "v1", credentials=creds)
            
            # List instances in all zones for this project
            request = compute.instances().aggregatedList(project=project_id)
            response = request.execute()
            
            project_instances = []
            for zone, zone_data in response.get('items', {}).items():
                if 'instances' in zone_data:
                    for instance in zone_data['instances']:
                        # Extract zone from the zone string
                        zone_name = zone.split('/')[-1] if '/' in zone else zone
                        
                        # Enrich instance data with security analysis
                        instance_info = {
                            'name': instance.get('name'),
                            'project': project_id,
                            'projectName': project.get('name', project_id),
                            'zone': zone_name,
                            'machineType': instance.get('machineType', '').split('/')[-1],
                            'status': instance.get('status'),
                            'creationTimestamp': instance.get('creationTimestamp'),
                            'networkInterfaces': instance.get('networkInterfaces', []),
                            'serviceAccounts': instance.get('serviceAccounts', []),
                            'metadata': instance.get('metadata', {}),
                            'tags': instance.get('tags', {}),
                            'scheduling': instance.get('scheduling', {}),
                            'disks': instance.get('disks', []),
                            'canIpForward': instance.get('canIpForward', False),
                            'selfLink': instance.get('selfLink'),
                            'riskLevel': 'UNKNOWN'
                        }
                        
                        # Assess security risk level
                        instance_info = _assess_compute_instance_risk(instance_info)
                        
                        project_instances.append(instance_info)
                        instances.append(instance_info)
            
            if not project_instances:
                print(f"[~] No compute instances found in {project_id}")
                continue
            
            # Print instances with risk assessment
            for instance in project_instances:
                risk_color = TerminalColors.RED if instance['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if instance['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                machine_type = instance['machineType']
                status = instance['status']
                zone = instance['zone']
                print(f"    {colorize('🖥️', risk_color)} {instance['name']} ({machine_type}, {status}, {zone}) - {colorize(instance['riskLevel'] + ' RISK', risk_color)}")
            
            high_risk = len([i for i in project_instances if i['riskLevel'] == 'HIGH'])
            medium_risk = len([i for i in project_instances if i['riskLevel'] == 'MEDIUM'])
            total_in_project = len(project_instances)
            print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} compute instances in {colorize(project_id, TerminalColors.CYAN)}")
            if high_risk > 0:
                print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk instances")
            if medium_risk > 0:
                print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk instances")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Compute Engine access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Compute Engine API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Compute Engine in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Compute Engine in {project_id}: {e}")
    
    # Final summary - CONDITIONAL
    total_instances = len(instances)
    high_risk_instances = len([i for i in instances if i['riskLevel'] == 'HIGH'])
    medium_risk_instances = len([i for i in instances if i['riskLevel'] == 'MEDIUM'])
    
    if total_instances > 0:  # Only show summary if instances exist
        print(f"\n{colorize('[+] COMPUTE INSTANCES ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('🖥️ Total Instances Discovered:', TerminalColors.BLUE)} {colorize(str(total_instances), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Instances:', TerminalColors.RED)} {colorize(str(high_risk_instances), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ MEDIUM-Risk Instances:', TerminalColors.YELLOW)} {colorize(str(medium_risk_instances), TerminalColors.WHITE)}")
    
    return instances

def _assess_compute_instance_risk(instance_info):
    """Assess security risk level of a compute instance."""
    risk_factors = 0
    
    # Public IP address
    network_interfaces = instance_info.get('networkInterfaces', [])
    for interface in network_interfaces:
        access_configs = interface.get('accessConfigs', [])
        if access_configs:
            risk_factors += 2  # Public IP is significant risk
            break
    
    # Default service account usage
    service_accounts = instance_info.get('serviceAccounts', [])
    for sa in service_accounts:
        sa_email = sa.get('email', '')
        if 'compute@developer.gserviceaccount.com' in sa_email:
            risk_factors += 2  # Default service account is overprivileged
        
        # Full cloud-platform scope
        scopes = sa.get('scopes', [])
        if 'https://www.googleapis.com/auth/cloud-platform' in scopes:
            risk_factors += 1
    
    # IP forwarding enabled
    if instance_info.get('canIpForward', False):
        risk_factors += 1
    
    # Preemptible instance (less secure for production)
    scheduling = instance_info.get('scheduling', {})
    if scheduling.get('preemptible', False):
        risk_factors += 1
    
    # SSH keys in metadata
    metadata = instance_info.get('metadata', {})
    metadata_items = metadata.get('items', [])
    for item in metadata_items:
        if item.get('key') in ['ssh-keys', 'sshKeys']:
            risk_factors += 1
            break
    
    # No network tags (poor network segmentation)
    tags = instance_info.get('tags', {})
    if not tags.get('items'):
        risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 4:
        instance_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        instance_info['riskLevel'] = 'MEDIUM'
    else:
        instance_info['riskLevel'] = 'LOW'
    
    return instance_info

def analyze_instance_privilege_escalation(creds, instances, service_accounts):
    """
    Analyze privilege escalation opportunities through compute instances.
    """
    escalation_analysis = []
    
    print(f"\n{colorize('[*] ANALYZING COMPUTE INSTANCE PRIVILEGE ESCALATION...', TerminalColors.CYAN)}")
    
    for instance in instances:
        instance_name = instance['name']
        project_id = instance['project']
        zone = instance['zone']
        
        instance_escalation = {
            'instance': instance_name,
            'project': project_id,
            'zone': zone,
            'serviceAccounts': [],
            'metadataAccess': False,
            'escalationRisk': 'LOW'
        }
        
        # Analyze service accounts attached to instance
        for sa_config in instance.get('serviceAccounts', []):
            sa_email = sa_config.get('email')
            scopes = sa_config.get('scopes', [])
            
            # Find corresponding service account from our enumeration
            matching_sa = next((sa for sa in service_accounts 
                              if sa.get('email') == sa_email), None)
            
            instance_escalation['serviceAccounts'].append({
                'email': sa_email,
                'scopes': scopes,
                'displayName': matching_sa.get('displayName', sa_email) if matching_sa else sa_email
            })
            
            # Check for high-privilege scenarios
            if 'compute@developer.gserviceaccount.com' in sa_email:
                print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} {instance_name}: Uses default Compute Engine service account")
                instance_escalation['escalationRisk'] = 'CRITICAL'
            elif 'https://www.googleapis.com/auth/cloud-platform' in scopes:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} {instance_name}: Has cloud-platform scope")
                if instance_escalation['escalationRisk'] not in ['CRITICAL']:
                    instance_escalation['escalationRisk'] = 'HIGH'
        
        # Check metadata server access potential
        network_interfaces = instance.get('networkInterfaces', [])
        has_public_ip = any(interface.get('accessConfigs') for interface in network_interfaces)
        
        if has_public_ip and instance_escalation['serviceAccounts']:
            instance_escalation['metadataAccess'] = True
            print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} {instance_name}: Public IP + service account = metadata server access")
            if instance_escalation['escalationRisk'] not in ['CRITICAL', 'HIGH']:
                instance_escalation['escalationRisk'] = 'MEDIUM'
        
        escalation_analysis.append(instance_escalation)
    
    # Summary
    critical_instances = len([i for i in escalation_analysis if i['escalationRisk'] == 'CRITICAL'])
    high_risk_instances = len([i for i in escalation_analysis if i['escalationRisk'] == 'HIGH'])
    medium_risk_instances = len([i for i in escalation_analysis if i['escalationRisk'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] COMPUTE INSTANCE PRIVILEGE ESCALATION SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('💀 CRITICAL Risk Instances:', TerminalColors.RED)} {colorize(str(critical_instances), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH Risk Instances:', TerminalColors.RED)} {colorize(str(high_risk_instances), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM Risk Instances:', TerminalColors.YELLOW)} {colorize(str(medium_risk_instances), TerminalColors.WHITE)}")
    
    return escalation_analysis

def build_compute_instance_edges(instances, instance_escalation_analysis, current_user):
    """
    Build BloodHound edges for compute instance relationships and privilege escalation paths.
    """
    edges = []
    
    for instance in instances:
        instance_name = instance['name']
        project_id = instance['project']
        zone = instance['zone']
        instance_id = f"gcp-compute-instance-{project_id}-{zone}-{instance_name}"
        
        # Edge: Instance belongs to project
        edges.append({
            "start": {"value": instance_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "compute_enumeration",
                "instanceName": instance_name,
                "zone": zone,
                "machineType": instance['machineType'],
                "status": instance['status'],
                "riskLevel": instance['riskLevel']
            }
        })
        
        # Edges: Instance uses service accounts
        for sa_config in instance.get('serviceAccounts', []):
            sa_email = sa_config.get('email')
            if sa_email:
                sa_id = sa_email.replace('@', '_').replace('.', '_')
                
                edges.append({
                    "start": {"value": instance_id},
                    "end": {"value": f"gcp-sa-{sa_id}"},
                    "kind": "UsesServiceAccount",
                    "properties": {
                        "source": "compute_enumeration",
                        "scopes": sa_config.get('scopes', []),
                        "description": f"Compute instance {instance_name} runs as service account {sa_email}"
                    }
                })
    
    # Edges for privilege escalation through instances
    for analysis in instance_escalation_analysis:
        instance_name = analysis['instance']
        project_id = analysis['project']
        zone = analysis['zone']
        instance_id = f"gcp-compute-instance-{project_id}-{zone}-{instance_name}"
        
        if analysis['escalationRisk'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
            # Edge: User can escalate privileges through compute instance
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": instance_id},
                "kind": "CanEscalateViaComputeInstance",
                "properties": {
                    "source": "compute_escalation_analysis",
                    "riskLevel": analysis['escalationRisk'],
                    "description": f"Can escalate privileges through compute instance {instance_name}",
                    "escalationMethods": {
                        "metadataAccess": analysis['metadataAccess'],
                        "serviceAccountCount": len(analysis['serviceAccounts'])
                    }
                }
            })
    
    return edges
