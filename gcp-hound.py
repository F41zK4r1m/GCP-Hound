from collectors.discovery import discover_projects_comprehensive, discover_apis_for_projects, assess_enumeration_capabilities
from collectors.service_account_collector import collect_service_accounts
from collectors.bucket_collector import collect_buckets
from collectors.secret_collector import collect_secrets, analyze_secret_access_privileges, build_secret_access_edges
from collectors.compute_collector import collect_compute_instances, analyze_instance_privilege_escalation, build_compute_instance_edges
from collectors.bigquery_collector import collect_bigquery_resources, analyze_bigquery_access_privileges, build_bigquery_edges
from collectors.gke_collector import collect_gke_clusters, analyze_gke_privilege_escalation, build_gke_edges
from collectors.users_groups_collector import collect_users_and_groups, analyze_users_groups_privilege_escalation, build_users_groups_edges
from collectors.sa_key_analyzer import analyze_service_account_key_access, build_key_access_edges
from collectors.privesc_analyzer import GCPPrivilegeEscalationAnalyzer, check_workspace_admin_status
from collectors.edge_builder import build_edges
from bloodhound.json_builder import export_bloodhound_json
from utils.auth import get_google_credentials, get_active_account

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

def main():
    creds = get_google_credentials()
    user = get_active_account(creds)
    print(f"[+] Running as: {user}")
    
    # Phase 1-3: Discovery and enumeration
    print(f"\n[*] 🔍 Reconnaissance Initiated")
    projects, discovery_method = discover_projects_comprehensive(creds)
    
    if not projects:
        print("[!] No projects discovered - cannot continue")
        return
    
    print(f"\n[*] Phase 2: API Capability Assessment")
    project_apis = discover_apis_for_projects(creds, projects)
    capabilities, enriched_project_data = assess_enumeration_capabilities(project_apis)
    
    # EARLY Admin Status Check with conditional logic
    admin_status = check_workspace_admin_status(creds)
    print(f"\n{colorize('[*] Google Workspace Admin Status Check:', TerminalColors.CYAN)}")
    if admin_status['hasAdminAccess']:
        print(f"    {colorize('✓ ADMIN ACCESS', TerminalColors.GREEN)}: {admin_status['adminLevel']}")
        has_admin_sdk_access = True
    else:
        error_msg = admin_status.get('error', 'Unknown error')
        print(f"    {colorize('✗ NO ADMIN ACCESS', TerminalColors.RED)}: {error_msg}")
        has_admin_sdk_access = False
    
    print(f"\n[*] Phase 3: Resource Enumeration")
    sacs = collect_service_accounts(creds, projects) if capabilities.get("Service Accounts") else []
    buckets = collect_buckets(creds, projects) if capabilities.get("Storage Buckets") else []  
    secrets = collect_secrets(creds, projects) if capabilities.get("Secrets") else []
    instances = collect_compute_instances(creds, projects) if capabilities.get("Compute Instances") else []
    bigquery_datasets = collect_bigquery_resources(creds, projects) if capabilities.get("BigQuery") else []
    gke_clusters = collect_gke_clusters(creds, projects) if capabilities.get("GKE Clusters") else []
    
    # CONDITIONAL Users/Groups enumeration
    if has_admin_sdk_access:
        users, groups, group_memberships = collect_users_and_groups(creds)
    else:
        print(f"\n{colorize('[*] Skipping Google Workspace user/group enumeration - Admin SDK access not available', TerminalColors.YELLOW)}")
        users, groups, group_memberships = [], [], []
    
    # Phase 4A: Service Account Key Analysis
    key_analysis = []
    if sacs:
        print(f"\n[*] Phase 4A: Service Account Key Access Analysis")
        key_analysis = analyze_service_account_key_access(creds, sacs)
    
    # Phase 4B: Secret Access Privilege Analysis
    secret_access_analysis = []
    if secrets and sacs:
        print(f"\n[*] Phase 4B: Secret Access Privilege Analysis")
        secret_access_analysis = analyze_secret_access_privileges(creds, secrets, sacs)
    
    # Phase 4C: Compute Instance Privilege Escalation Analysis
    instance_escalation_analysis = []
    if instances and sacs:
        print(f"\n[*] Phase 4C: Compute Instance Privilege Escalation Analysis")
        instance_escalation_analysis = analyze_instance_privilege_escalation(creds, instances, sacs)
    
    # Phase 4D: BigQuery Access Privilege Analysis
    bigquery_access_analysis = []
    if bigquery_datasets and sacs:
        print(f"\n[*] Phase 4D: BigQuery Access Privilege Analysis")
        bigquery_access_analysis = analyze_bigquery_access_privileges(creds, bigquery_datasets, sacs)
    
    # Phase 4E: GKE Cluster Privilege Escalation Analysis
    gke_escalation_analysis = []
    if gke_clusters and sacs:
        print(f"\n[*] Phase 4E: GKE Cluster Privilege Escalation Analysis")
        gke_escalation_analysis = analyze_gke_privilege_escalation(creds, gke_clusters, sacs)
    
    # Phase 4F: Users/Groups Privilege Escalation Analysis
    users_groups_escalation = {}
    if users and sacs:
        print(f"\n[*] Phase 4F: Users/Groups Privilege Escalation Analysis")
        users_groups_escalation = analyze_users_groups_privilege_escalation(users, groups, group_memberships, sacs)
    
    # Phase 4G: Comprehensive Privilege Escalation Analysis
    print(f"\n[*] Phase 4G: 🚨 COMPREHENSIVE PRIVILEGE ESCALATION ANALYSIS")
    privesc_analyzer = GCPPrivilegeEscalationAnalyzer(creds)
    escalation_results = privesc_analyzer.analyze_all_privilege_escalation_paths(projects, sacs)
    
    # Phase 5: Build ALL edges
    print(f"\n[*] Phase 5: Building Complete Attack Path Graph")
    base_edges = build_edges(projects, [], [], sacs, buckets, secrets)
    key_access_edges = build_key_access_edges(sacs, key_analysis, user) if key_analysis else []
    secret_access_edges = build_secret_access_edges(secrets, secret_access_analysis, user) if secret_access_analysis else []
    compute_edges = build_compute_instance_edges(instances, instance_escalation_analysis, user) if instances else []
    bigquery_edges = build_bigquery_edges(bigquery_datasets, bigquery_access_analysis, user) if bigquery_datasets else []
    gke_edges = build_gke_edges(gke_clusters, gke_escalation_analysis, user) if gke_clusters else []
    users_groups_edges = build_users_groups_edges(users, groups, group_memberships, users_groups_escalation, user) if users else []
    escalation_edges = privesc_analyzer.build_escalation_edges(user)
    
    all_edges = base_edges + key_access_edges + secret_access_edges + compute_edges + bigquery_edges + gke_edges + users_groups_edges + escalation_edges
    
    # Phase 6: Export comprehensive BloodHound data
    export_bloodhound_json([], [], projects, [], sacs, buckets, secrets, all_edges)
    
    # Final comprehensive summary
    total_escalation_paths = sum(len(r['critical_paths']) + len(r['high_risk_paths']) for r in escalation_results)
    
    print(f"\n[+] 🎯 COMPREHENSIVE GCP ATTACK SURFACE ANALYSIS COMPLETE:")
    print(f"    Projects: {len(projects)}")
    print(f"    Service Accounts: {len(sacs)}")
    print(f"    Storage Buckets: {len(buckets)}")
    print(f"    Secrets: {len(secrets)}")
    print(f"    Compute Instances: {len(instances)}")
    print(f"    BigQuery Datasets: {len(bigquery_datasets)}")
    print(f"    GKE Clusters: {len(gke_clusters)}")
    print(f"    Users: {len(users)}")
    print(f"    Groups: {len(groups)}")
    print(f"    Service Account Key Analysis: {len(key_analysis)} analyzed")
    print(f"    Secret Access Analysis: {len(secret_access_analysis)} secrets analyzed")
    print(f"    Instance Escalation Analysis: {len(instance_escalation_analysis)} instances analyzed")
    print(f"    BigQuery Access Analysis: {len(bigquery_access_analysis)} datasets analyzed")
    print(f"    GKE Escalation Analysis: {len(gke_escalation_analysis)} clusters analyzed")
    print(f"    Users/Groups Escalation Analysis: {len(users)} users, {len(groups)} groups analyzed")
    print(f"    Privilege Escalation Paths: {total_escalation_paths}")
    print(f"    Base Relationship Edges: {len(base_edges)}")
    print(f"    Key Access Edges: {len(key_access_edges)}")
    print(f"    Secret Access Edges: {len(secret_access_edges)}")
    print(f"    Compute Instance Edges: {len(compute_edges)}")
    print(f"    BigQuery Access Edges: {len(bigquery_edges)}")
    print(f"    GKE Cluster Edges: {len(gke_edges)}")
    print(f"    Users/Groups Edges: {len(users_groups_edges)}")
    print(f"    Advanced Escalation Edges: {len(escalation_edges)}")
    print(f"    Total BloodHound Attack Edges: {len(all_edges)}")
    print(f"\n[+] BloodHound attack graph: ./output/gcp-graph.json")

if __name__ == '__main__':
    main()
