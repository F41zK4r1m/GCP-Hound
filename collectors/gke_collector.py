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

def collect_gke_clusters(creds, projects):
    """
    Enumerate all GKE clusters across accessible projects.
    Returns a list of cluster dicts with security analysis.
    """
    clusters = []
    
    print(f"\n{colorize('[*] ENUMERATING GKE CLUSTERS...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build GKE Container API client
            container = build("container", "v1", credentials=creds)
            
            # List clusters in all locations for this project
            request = container.projects().locations().clusters().list(
                parent=f"projects/{project_id}/locations/-"
            )
            response = request.execute()
            project_clusters = response.get('clusters', [])
            
            if not project_clusters:
                print(f"[~] No GKE clusters found in {project_id}")
                continue
            
            for cluster in project_clusters:
                # Extract comprehensive cluster information
                cluster_info = {
                    'name': cluster.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'location': cluster.get('location'),
                    'endpoint': cluster.get('endpoint'),
                    'status': cluster.get('status'),
                    'currentMasterVersion': cluster.get('currentMasterVersion'),
                    'currentNodeVersion': cluster.get('currentNodeVersion'),
                    'createTime': cluster.get('createTime'),
                    'nodeConfig': cluster.get('nodeConfig', {}),
                    'masterAuth': cluster.get('masterAuth', {}),
                    'loggingService': cluster.get('loggingService'),
                    'monitoringService': cluster.get('monitoringService'),
                    'network': cluster.get('network'),
                    'clusterIpv4Cidr': cluster.get('clusterIpv4Cidr'),
                    'addonsConfig': cluster.get('addonsConfig', {}),
                    'subnetwork': cluster.get('subnetwork'),
                    'nodePools': cluster.get('nodePools', []),
                    'locations': cluster.get('locations', []),
                    'enableTpu': cluster.get('enableTpu', False),
                    'networkPolicy': cluster.get('networkPolicy', {}),
                    'ipAllocationPolicy': cluster.get('ipAllocationPolicy', {}),
                    'masterAuthorizedNetworksConfig': cluster.get('masterAuthorizedNetworksConfig', {}),
                    'privateClusterConfig': cluster.get('privateClusterConfig', {}),
                    'databaseEncryption': cluster.get('databaseEncryption', {}),
                    'shieldedNodes': cluster.get('shieldedNodes', {}),
                    'workloadIdentityConfig': cluster.get('workloadIdentityConfig', {}),
                    'riskLevel': 'UNKNOWN'
                }
                
                # Perform security analysis
                cluster_info = _analyze_gke_cluster_security(cluster_info)
                
                clusters.append(cluster_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if cluster_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if cluster_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                node_pools = len(cluster_info['nodePools'])
                version = cluster_info['currentMasterVersion']
                print(f"    {colorize('⚙️', risk_color)} {cluster_info['name']} ({cluster_info['location']}, {node_pools} pools, v{version}) - {colorize(cluster_info['riskLevel'] + ' RISK', risk_color)}")
            
            if project_clusters:
                high_risk = len([c for c in clusters if c.get('project') == project_id and c['riskLevel'] == 'HIGH'])
                medium_risk = len([c for c in clusters if c.get('project') == project_id and c['riskLevel'] == 'MEDIUM'])
                total_in_project = len([c for c in clusters if c.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} GKE clusters in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk clusters")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk clusters")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Container/GKE access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Container API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing GKE in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing GKE in {project_id}: {e}")
    
    # Final summary - CONDITIONAL
    total_clusters = len(clusters)
    high_risk_clusters = len([c for c in clusters if c['riskLevel'] == 'HIGH'])
    medium_risk_clusters = len([c for c in clusters if c['riskLevel'] == 'MEDIUM'])
    total_node_pools = sum(len(c['nodePools']) for c in clusters)
    
    if total_clusters > 0:  # Only show summary if clusters exist
        print(f"\n{colorize('[+] GKE CLUSTERS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('⚙️ Total Clusters Discovered:', TerminalColors.BLUE)} {colorize(str(total_clusters), TerminalColors.WHITE)}")
        print(f"    {colorize('🔗 Total Node Pools:', TerminalColors.BLUE)} {colorize(str(total_node_pools), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Clusters:', TerminalColors.RED)} {colorize(str(high_risk_clusters), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ MEDIUM-Risk Clusters:', TerminalColors.YELLOW)} {colorize(str(medium_risk_clusters), TerminalColors.WHITE)}")
    
    return clusters

def _analyze_gke_cluster_security(cluster_info):
    """Analyze security posture of a GKE cluster."""
    risk_factors = 0
    
    # High risk factors
    master_auth = cluster_info.get('masterAuth', {})
    node_config = cluster_info.get('nodeConfig', {})
    private_cluster_config = cluster_info.get('privateClusterConfig', {})
    
    # Legacy ABAC enabled (deprecated and insecure)
    if master_auth.get('username') or master_auth.get('password'):
        risk_factors += 3  # Legacy basic auth is critical risk
    
    # Client certificate authentication enabled
    if master_auth.get('clientCertificateConfig', {}).get('issueClientCertificate'):
        risk_factors += 2  # Client certs can be risky if not managed properly
    
    # No network policy (allows unrestricted pod-to-pod communication)
    network_policy = cluster_info.get('networkPolicy', {})
    if not network_policy.get('enabled', False):
        risk_factors += 1
    
    # Not a private cluster (nodes have public IPs)
    if not private_cluster_config.get('enablePrivateNodes', False):
        risk_factors += 2
    
    # No master authorized networks (API server accessible from anywhere)
    master_authorized_networks = cluster_info.get('masterAuthorizedNetworksConfig', {})
    if not master_authorized_networks.get('enabled', False):
        risk_factors += 2
    
    # Workload Identity not enabled (pods use node service account)
    workload_identity = cluster_info.get('workloadIdentityConfig', {})
    if not workload_identity.get('workloadPool'):
        risk_factors += 1
    
    # Database encryption not enabled
    db_encryption = cluster_info.get('databaseEncryption', {})
    if db_encryption.get('state') != 'ENCRYPTED':
        risk_factors += 1
    
    # Shielded nodes not enabled
    shielded_nodes = cluster_info.get('shieldedNodes', {})
    if not shielded_nodes.get('enabled', False):
        risk_factors += 1
    
    # Analyze node pools for security issues
    for node_pool in cluster_info.get('nodePools', []):
        pool_config = node_pool.get('config', {})
        
        # Node service account is default compute service account (overprivileged)
        service_account = pool_config.get('serviceAccount')
        if not service_account or 'compute@developer.gserviceaccount.com' in service_account:
            risk_factors += 2
        
        # OAuth scopes include cloud-platform (overprivileged)
        oauth_scopes = pool_config.get('oauthScopes', [])
        if 'https://www.googleapis.com/auth/cloud-platform' in oauth_scopes:
            risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 6:
        cluster_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 3:
        cluster_info['riskLevel'] = 'MEDIUM'
    else:
        cluster_info['riskLevel'] = 'LOW'
    
    return cluster_info

def analyze_gke_privilege_escalation(creds, clusters, service_accounts):
    """
    Analyze privilege escalation opportunities through GKE clusters.
    """
    escalation_analysis = []
    
    print(f"\n{colorize('[*] ANALYZING GKE PRIVILEGE ESCALATION PATHS...', TerminalColors.CYAN)}")
    
    for cluster in clusters:
        cluster_name = cluster['name']
        project_id = cluster['project']
        location = cluster['location']
        
        cluster_escalation = {
            'cluster': cluster_name,
            'project': project_id,
            'location': location,
            'nodePoolServiceAccounts': [],
            'workloadIdentityEnabled': False,
            'privateCluster': False,
            'escalationRisk': 'LOW'
        }
        
        # Analyze workload identity configuration
        workload_identity = cluster.get('workloadIdentityConfig', {})
        cluster_escalation['workloadIdentityEnabled'] = bool(workload_identity.get('workloadPool'))
        
        # Analyze private cluster configuration
        private_config = cluster.get('privateClusterConfig', {})
        cluster_escalation['privateCluster'] = private_config.get('enablePrivateNodes', False)
        
        # Analyze node pool service accounts
        for node_pool in cluster.get('nodePools', []):
            pool_name = node_pool.get('name')
            pool_config = node_pool.get('config', {})
            service_account = pool_config.get('serviceAccount')
            oauth_scopes = pool_config.get('oauthScopes', [])
            
            if service_account:
                # Find matching service account from our enumeration
                matching_sa = next((sa for sa in service_accounts 
                                  if sa.get('email') == service_account), None)
                
                cluster_escalation['nodePoolServiceAccounts'].append({
                    'nodePool': pool_name,
                    'serviceAccount': service_account,
                    'oauthScopes': oauth_scopes,
                    'displayName': matching_sa.get('displayName', service_account) if matching_sa else service_account
                })
                
                # Check for high-privilege scenarios
                if 'compute@developer.gserviceaccount.com' in service_account:
                    print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} {cluster_name}: Uses default Compute Engine service account")
                    cluster_escalation['escalationRisk'] = 'CRITICAL'
                elif 'https://www.googleapis.com/auth/cloud-platform' in oauth_scopes:
                    print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} {cluster_name}: Node pool has cloud-platform OAuth scope")
                    if cluster_escalation['escalationRisk'] not in ['CRITICAL']:
                        cluster_escalation['escalationRisk'] = 'HIGH'
        
        # Additional risk factors
        if not cluster_escalation['workloadIdentityEnabled']:
            print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} {cluster_name}: Workload Identity not enabled - pods inherit node SA permissions")
            if cluster_escalation['escalationRisk'] not in ['CRITICAL', 'HIGH']:
                cluster_escalation['escalationRisk'] = 'MEDIUM'
        
        if not cluster_escalation['privateCluster']:
            print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} {cluster_name}: Not a private cluster - nodes have public IPs")
        
        escalation_analysis.append(cluster_escalation)
    
    # Summary
    critical_clusters = len([c for c in escalation_analysis if c['escalationRisk'] == 'CRITICAL'])
    high_risk_clusters = len([c for c in escalation_analysis if c['escalationRisk'] == 'HIGH'])
    medium_risk_clusters = len([c for c in escalation_analysis if c['escalationRisk'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] GKE PRIVILEGE ESCALATION SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('💀 CRITICAL Risk Clusters:', TerminalColors.RED)} {colorize(str(critical_clusters), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH Risk Clusters:', TerminalColors.RED)} {colorize(str(high_risk_clusters), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM Risk Clusters:', TerminalColors.YELLOW)} {colorize(str(medium_risk_clusters), TerminalColors.WHITE)}")
    
    return escalation_analysis

def build_gke_edges(clusters, gke_escalation_analysis, current_user):
    """
    Build BloodHound edges for GKE cluster relationships and privilege escalation paths.
    """
    edges = []
    
    for cluster in clusters:
        cluster_name = cluster['name']
        project_id = cluster['project']
        cluster_id = f"gcp-gke-cluster-{project_id}-{cluster_name}"
        
        # Edge: Cluster belongs to project
        edges.append({
            "start": {"value": cluster_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "gke_enumeration",
                "clusterName": cluster_name,
                "location": cluster['location'],
                "status": cluster['status'],
                "riskLevel": cluster['riskLevel'],
                "masterVersion": cluster.get('currentMasterVersion', 'unknown')
            }
        })
        
        # Edges: Node pools use service accounts
        for node_pool in cluster.get('nodePools', []):
            pool_config = node_pool.get('config', {})
            service_account = pool_config.get('serviceAccount')
            
            if service_account:
                sa_id = service_account.replace('@', '_').replace('.', '_')
                node_pool_id = f"gcp-gke-nodepool-{project_id}-{cluster_name}-{node_pool.get('name')}"
                
                # Edge: Node pool belongs to cluster
                edges.append({
                    "start": {"value": node_pool_id},
                    "end": {"value": cluster_id},
                    "kind": "BelongsTo",
                    "properties": {
                        "source": "gke_enumeration",
                        "nodePoolName": node_pool.get('name'),
                        "machineType": pool_config.get('machineType', 'unknown'),
                        "nodeCount": node_pool.get('initialNodeCount', 0)
                    }
                })
                
                # Edge: Node pool uses service account
                edges.append({
                    "start": {"value": node_pool_id},
                    "end": {"value": f"gcp-sa-{sa_id}"},
                    "kind": "UsesServiceAccount",
                    "properties": {
                        "source": "gke_enumeration",
                        "oauthScopes": pool_config.get('oauthScopes', []),
                        "description": f"GKE node pool {node_pool.get('name')} runs as service account {service_account}"
                    }
                })
    
    # Edges for privilege escalation through GKE clusters
    for analysis in gke_escalation_analysis:
        cluster_name = analysis['cluster']
        project_id = analysis['project']
        cluster_id = f"gcp-gke-cluster-{project_id}-{cluster_name}"
        
        if analysis['escalationRisk'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
            # Edge: User can escalate privileges through GKE cluster
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": cluster_id},
                "kind": "CanEscalateViaGKECluster",
                "properties": {
                    "source": "gke_escalation_analysis",
                    "riskLevel": analysis['escalationRisk'],
                    "description": f"Can escalate privileges through GKE cluster {cluster_name}",
                    "escalationMethods": {
                        "workloadIdentityEnabled": analysis['workloadIdentityEnabled'],
                        "privateCluster": analysis['privateCluster'],
                        "nodePoolCount": len(analysis['nodePoolServiceAccounts'])
                    }
                }
            })
    
    return edges
