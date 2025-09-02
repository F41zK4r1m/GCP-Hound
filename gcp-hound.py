#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import argparse
import logging
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
from collectors.iam_collector import collect_iam, analyze_cross_project_permissions  # ← NEW IMPORT
from collectors.user_collector import collect_users  # ← NEW IMPORT
from collectors.folder_collector import collect_folders, build_folder_edges  # ← NEW IMPORT
from bloodhound.json_builder import export_bloodhound_json
from utils.auth import get_google_credentials, get_active_account
from google.auth import impersonated_credentials
import google.auth
import google.auth.exceptions

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

def setup_impersonation(service_account_email, verbose=False):
    """Setup impersonated credentials for a service account"""
    try:
        if verbose:
            print(f"[*] Attempting to impersonate: {service_account_email}")
        
        source_credentials, project = google.auth.default()
        target_credentials = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=service_account_email,
            target_scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        
        from google.auth.transport.requests import Request
        target_credentials.refresh(Request())
        
        if verbose:
            print(f"[*] ✅ Successfully impersonating: {service_account_email}")
        return target_credentials
    except google.auth.exceptions.GoogleAuthError as e:
        print(f"[!] ❌ Failed to impersonate {service_account_email}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="GCP-Hound - Google Cloud Platform Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔐 GCP-Hound performs comprehensive GCP security analysis including:

AUTHENTICATION:
  Before running GCP-Hound, you must authenticate with Google Cloud:

  Option A: Application Default Credentials (Recommended)
    $ gcloud auth application-default login
    
  Option B: Service Account Key File
    $ export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
    
  Option C: Impersonate Service Account (with -i flag)
    $ python3 gcp-hound.py -i target-service@project.iam.gserviceaccount.com
    
  Required Permissions: The authenticated identity needs permissions to:
    • List projects, service accounts, IAM policies
    • Read storage buckets, secrets, compute instances
    • Access BigQuery datasets, GKE clusters
    • (Optional) Google Workspace Admin API for user/group enumeration

ENUMERATION PHASES:
  Phase 1-3: Project discovery, API assessment, resource enumeration
  Phase 4A:  Service account key access analysis  
  Phase 4B:  Secret access privilege analysis
  Phase 4C:  Compute instance privilege escalation analysis
  Phase 4D:  BigQuery access privilege analysis
  Phase 4E:  GKE cluster privilege escalation analysis
  Phase 4F:  Users/Groups privilege escalation analysis
  Phase 4G:  Comprehensive privilege escalation analysis
  Phase 5:   Complete attack path graph building
  Phase 6:   BloodHound export with custom GCP icons

RESOURCES COVERED:
  • Projects, Service Accounts, Storage Buckets, Secrets
  • Compute Instances, BigQuery Datasets, GKE Clusters  
  • Users/Groups (with Workspace Admin detection)
  • 20+ different attack relationship types

Examples:
  # First authenticate
  $ gcloud auth application-default login
  
  # Then run analysis
  python3 gcp-hound.py                                    # Full comprehensive analysis
  python3 gcp-hound.py -v                                 # Verbose progress output
  python3 gcp-hound.py -d                                 # Debug technical details
  python3 gcp-hound.py -p my-gcp-project                  # Target specific project  
  python3 gcp-hound.py -i user@project.iam.gserviceaccount.com  # Impersonate service account
  python3 gcp-hound.py -v -d -o /tmp/results              # Verbose debug with custom output

For more authentication details: https://cloud.google.com/docs/authentication
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output (shows detailed progress)')
    parser.add_argument('-d', '--debug', action='store_true', 
                       help='Enable debug output (shows technical details)')
    parser.add_argument('-i', '--impersonate', type=str,
                       help='Impersonate service account (e.g., user@project.iam.gserviceaccount.com)')
    parser.add_argument('-p', '--project', type=str,
                       help='Target specific GCP project ID')
    parser.add_argument('-o', '--output', type=str, default='./output',
                       help='Output directory for results (default: ./output)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress banner and minimize output')
    parser.add_argument('--no-icons', action='store_true',
                       help='Skip BloodHound icon registration')
    
    args = parser.parse_args()

    # Setup logging
    log_level = logging.WARNING
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    logger = logging.getLogger("GCP-Hound")

    # Print banner unless quiet mode
    if not args.quiet:
        print()
        print("🔐 GCP-Hound - Google Cloud Platform Security Assessment Tool")
        print("=" * 80)
        print("🎯 Comprehensive GCP Attack Surface Analysis & Privilege Escalation Detection")
        print("=" * 80)
        
        if args.verbose:
            print(f"[*] Verbose mode: Enabled")
        if args.debug:  
            print(f"[*] Debug mode: Enabled")
        if args.project:
            print(f"[*] Target project: {args.project}")
        if args.impersonate:
            print(f"[*] Impersonation target: {args.impersonate}")
        print(f"[*] Output directory: {args.output}")
        print()

    try:
        # Setup credentials (with impersonation support)
        if args.impersonate:
            creds = setup_impersonation(args.impersonate, args.verbose)
            if not creds:
                print("[!] Impersonation failed. Exiting.")
                sys.exit(1)
            user = args.impersonate
        else:
            creds = get_google_credentials()
            user = get_active_account(creds)
        
        print(f"[+] Running as: {colorize(user, TerminalColors.GREEN)}")
        
        # Phase 1-3: Discovery and enumeration
        print(f"\n[*] 🔍 {colorize('Phase 1-3: Reconnaissance & Resource Discovery', TerminalColors.CYAN)}")
        projects, discovery_method = discover_projects_comprehensive(creds)
        
        if not projects:
            print(f"{colorize('[!] No projects discovered - cannot continue', TerminalColors.RED)}")
            return
        
        if args.verbose:
            print(f"[*] Discovered {len(projects)} projects using {discovery_method}")

        # Apply project filter if specified
        if args.project:
            original_count = len(projects)
            projects = [p for p in projects if p.get('projectId') == args.project]
            if not projects:
                print(f"{colorize(f'[!] Target project {args.project} not found or not accessible', TerminalColors.RED)}")
                return
            if args.verbose:
                print(f"[*] Filtered to target project: {args.project} (was {original_count} projects)")

        print(f"\n[*] Phase 2: API Capability Assessment")
        project_apis = discover_apis_for_projects(creds, projects)
        capabilities, enriched_project_data = assess_enumeration_capabilities(project_apis)
        
        if args.verbose:
            enabled_apis = [k for k, v in capabilities.items() if v]
            print(f"[*] Enabled capabilities: {', '.join(enabled_apis)}")

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
        
        # ← NEW: Add IAM collection
        print(f"\n[*] Phase 3A: IAM Policy Enumeration")
        iam_data = collect_iam(creds, projects)
        outbound_permissions = analyze_cross_project_permissions(creds, user, projects)
        
        # ← NEW: Add folder collection
        print(f"\n[*] Phase 3B: Organizational Structure Enumeration")
        folders, folder_hierarchy = collect_folders(creds, [])  # Pass empty for org auto-discovery
        
        if args.verbose:
            print(f"[*] Found: {len(sacs)} SAs, {len(buckets)} buckets, {len(secrets)} secrets")
            print(f"[*] Found: {len(instances)} instances, {len(bigquery_datasets)} datasets, {len(gke_clusters)} clusters")
            print(f"[*] Found IAM data for {len(iam_data)} projects")  # ← NEW
            print(f"[*] Found outbound control capabilities in {len(outbound_permissions)} projects")  # ← NEW
            print(f"[*] Found {len(folders)} folders in organizational hierarchy")  # ← NEW

        # CONDITIONAL Users/Groups enumeration
        if has_admin_sdk_access:
            users, groups, group_memberships = collect_users(creds, projects)  # ← UPDATED IMPORT
            if args.verbose:
                print(f"[*] Found: {len(users)} users, {len(groups)} groups")
        else:
            print(f"\n{colorize('[*] Skipping Google Workspace user/group enumeration - Admin SDK access not available', TerminalColors.YELLOW)}")
            users, groups, group_memberships = [], [], []

        # Phase 4A: Service Account Key Analysis
        key_analysis = []
        if sacs:
            print(f"\n[*] Phase 4A: Service Account Key Access Analysis")
            key_analysis = analyze_service_account_key_access(creds, sacs)
            if args.verbose:
                print(f"[*] Analyzed key access for {len(sacs)} service accounts")

        # Phase 4B: Secret Access Privilege Analysis
        secret_access_analysis = []
        if secrets and sacs:
            print(f"\n[*] Phase 4B: Secret Access Privilege Analysis")
            secret_access_analysis = analyze_secret_access_privileges(creds, secrets, sacs)
            if args.verbose:
                print(f"[*] Analyzed secret access for {len(secrets)} secrets")

        # Phase 4C: Compute Instance Privilege Escalation Analysis
        instance_escalation_analysis = []
        if instances and sacs:
            print(f"\n[*] Phase 4C: Compute Instance Privilege Escalation Analysis")
            instance_escalation_analysis = analyze_instance_privilege_escalation(creds, instances, sacs)
            if args.verbose:
                print(f"[*] Analyzed escalation for {len(instances)} instances")

        # Phase 4D: BigQuery Access Privilege Analysis
        bigquery_access_analysis = []
        if bigquery_datasets and sacs:
            print(f"\n[*] Phase 4D: BigQuery Access Privilege Analysis")
            bigquery_access_analysis = analyze_bigquery_access_privileges(creds, bigquery_datasets, sacs)
            if args.verbose:
                print(f"[*] Analyzed BigQuery access for {len(bigquery_datasets)} datasets")

        # Phase 4E: GKE Cluster Privilege Escalation Analysis
        gke_escalation_analysis = []
        if gke_clusters and sacs:
            print(f"\n[*] Phase 4E: GKE Cluster Privilege Escalation Analysis")
            gke_escalation_analysis = analyze_gke_privilege_escalation(creds, gke_clusters, sacs)
            if args.verbose:
                print(f"[*] Analyzed GKE escalation for {len(gke_clusters)} clusters")

        # Phase 4F: Users/Groups Privilege Escalation Analysis
        users_groups_escalation = {}
        if users and sacs:
            print(f"\n[*] Phase 4F: Users/Groups Privilege Escalation Analysis")
            users_groups_escalation = analyze_users_groups_privilege_escalation(users, groups, group_memberships, sacs)
            if args.verbose:
                print(f"[*] Analyzed user/group escalation for {len(users)} users")

        # Phase 4G: Comprehensive Privilege Escalation Analysis
        print(f"\n[*] Phase 4G: 🚨 {colorize('COMPREHENSIVE PRIVILEGE ESCALATION ANALYSIS', TerminalColors.BOLD + TerminalColors.RED)}")
        privesc_analyzer = GCPPrivilegeEscalationAnalyzer(creds)
        escalation_results = privesc_analyzer.analyze_all_privilege_escalation_paths(projects, sacs)
        
        # Phase 5: Build ALL edges
        print(f"\n[*] Phase 5: Building Complete Attack Path Graph")
        base_edges = build_edges(projects, iam_data, [], sacs, buckets, secrets)  # ← UPDATED: Pass iam_data
        key_access_edges = build_key_access_edges(sacs, key_analysis, user) if key_analysis else []
        secret_access_edges = build_secret_access_edges(secrets, secret_access_analysis, user) if secret_access_analysis else []
        compute_edges = build_compute_instance_edges(instances, instance_escalation_analysis, user) if instances else []
        bigquery_edges = build_bigquery_edges(bigquery_datasets, bigquery_access_analysis, user) if bigquery_datasets else []
        gke_edges = build_gke_edges(gke_clusters, gke_escalation_analysis, user) if gke_clusters else []
        users_groups_edges = build_users_groups_edges(users, groups, group_memberships, users_groups_escalation, user) if users else []
        escalation_edges = privesc_analyzer.build_escalation_edges(user)
        folder_edges = build_folder_edges(folders, folder_hierarchy, projects)  # ← NEW: Add folder edges
        
        all_edges = base_edges + key_access_edges + secret_access_edges + compute_edges + bigquery_edges + gke_edges + users_groups_edges + escalation_edges + folder_edges  # ← UPDATED: Include folder_edges
        
        if args.verbose:
            print(f"[*] Built {len(all_edges)} total attack relationships")

        # Phase 6: Export comprehensive BloodHound data
        print(f"\n[*] Phase 6: BloodHound Export")
        
        # Create output directory
        if not os.path.exists(args.output):
            os.makedirs(args.output)
            
        output_file = export_bloodhound_json([], users, projects, groups, sacs, buckets, secrets, all_edges, creds, iam_data)
        
        # Final comprehensive summary
        total_escalation_paths = sum(len(r.get('critical_paths', [])) + len(r.get('high_risk_paths', [])) for r in escalation_results)
        critical_edges = len([e for e in all_edges if e.get('properties', {}).get('riskLevel') == 'CRITICAL'])
        
        print(f"\n" + "=" * 80)
        print(f"🎯 {colorize('COMPREHENSIVE GCP ATTACK SURFACE ANALYSIS COMPLETE', TerminalColors.BOLD + TerminalColors.GREEN)}")
        print(f"=" * 80)
        print(f"📊 {colorize('RESOURCE INVENTORY:', TerminalColors.CYAN)}")
        print(f"    Projects: {len(projects)}")
        print(f"    Service Accounts: {len(sacs)}")
        print(f"    Storage Buckets: {len(buckets)}")
        print(f"    Secrets: {len(secrets)}")
        print(f"    Compute Instances: {len(instances)}")
        print(f"    BigQuery Datasets: {len(bigquery_datasets)}")
        print(f"    GKE Clusters: {len(gke_clusters)}")
        print(f"    Users: {len(users)}")
        print(f"    Groups: {len(groups)}")
        print(f"    IAM Bindings: {sum(len(iam.get('bindings', [])) for iam in iam_data)}")  # ← NEW
        print(f"    Folders: {len(folders)}")  # ← NEW
        print()
        print(f"🔍 {colorize('SECURITY ANALYSIS:', TerminalColors.CYAN)}")
        print(f"    Service Account Key Analysis: {len(key_analysis)} analyzed")
        print(f"    Secret Access Analysis: {len(secret_access_analysis)} secrets analyzed")
        print(f"    Instance Escalation Analysis: {len(instance_escalation_analysis)} instances analyzed")
        print(f"    BigQuery Access Analysis: {len(bigquery_access_analysis)} datasets analyzed")
        print(f"    GKE Escalation Analysis: {len(gke_escalation_analysis)} clusters analyzed")
        print(f"    Users/Groups Escalation Analysis: {len(users)} users, {len(groups)} groups analyzed")
        print(f"    IAM Policy Analysis: {len(iam_data)} projects analyzed")  # ← NEW
        print(f"    Outbound Control Analysis: {len(outbound_permissions)} projects with permissions")  # ← NEW
        print(f"    Organizational Structure Analysis: {len(folders)} folders analyzed")  # ← NEW
        if total_escalation_paths > 0:
            print(f"    {colorize(f'Privilege Escalation Paths: {total_escalation_paths}', TerminalColors.YELLOW)}")
        print()
        print(f"🔗 {colorize('ATTACK GRAPH:', TerminalColors.CYAN)}")
        print(f"    Base Relationship Edges: {len(base_edges)}")
        print(f"    Key Access Edges: {len(key_access_edges)}")
        print(f"    Secret Access Edges: {len(secret_access_edges)}")
        print(f"    Compute Instance Edges: {len(compute_edges)}")
        print(f"    BigQuery Access Edges: {len(bigquery_edges)}")
        print(f"    GKE Cluster Edges: {len(gke_edges)}")
        print(f"    Users/Groups Edges: {len(users_groups_edges)}")
        print(f"    Advanced Escalation Edges: {len(escalation_edges)}")
        print(f"    Folder Relationship Edges: {len(folder_edges)}")  # ← NEW
        print(f"    {colorize(f'Total BloodHound Attack Edges: {len(all_edges)}', TerminalColors.BOLD)}")
        if critical_edges > 0:
            print(f"    {colorize(f'🚨 CRITICAL Attack Paths: {critical_edges}', TerminalColors.RED + TerminalColors.BOLD)}")
        print()
        print(f"📁 {colorize('OUTPUT:', TerminalColors.CYAN)}")
        print(f"    BloodHound JSON: {output_file}")
        print(f"    Custom GCP Icons: {'Registered' if not args.no_icons else 'Skipped'}")
        print()
        print(f"💡 {colorize('NEXT STEPS:', TerminalColors.CYAN)}")
        print(f"    1. Upload {output_file} to BloodHound")
        print(f"    2. Run queries to visualize attack paths")
        print(f"    3. Focus on CRITICAL risk findings first")
        print("=" * 80)

    except KeyboardInterrupt:
        print(f"\n{colorize('[!] Analysis interrupted by user', TerminalColors.YELLOW)}")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            import traceback
            print(f"\n{colorize('[!] Analysis failed with detailed error:', TerminalColors.RED)}")
            traceback.print_exc()
        else:
            print(f"\n{colorize(f'[!] Analysis failed: {e}', TerminalColors.RED)}")
            print(f"[!] Use -d flag for detailed error information")
        sys.exit(1)

if __name__ == '__main__':
    main()
