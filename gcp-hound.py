#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import argparse
import logging
import urllib3
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
from collectors.iam_collector import collect_iam, analyze_cross_project_permissions
from collectors.user_collector import collect_users
from collectors.folder_collector import collect_folders, build_folder_edges
from collectors.logging_collector import collect_logging_resources, analyze_logging_access_privileges, build_logging_edges
from bloodhound.json_builder import export_bloodhound_json
from utils.auth import get_google_credentials, get_active_account
from google.auth import impersonated_credentials
from googleapiclient.errors import HttpError
import google.auth
import google.auth.exceptions
import requests

# Disable urllib3 warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def handle_api_error(e, context="API call", args=None):
    """Centralized error handling for GCP API calls"""
    if args and args.debug:
        logger = logging.getLogger("GCP-Hound")
        logger.warning(f"[DEBUG] {context}: {str(e)}")
        return False
    elif isinstance(e, HttpError) and e.status_code == 403:
        if "SERVICE_DISABLED" in str(e):
            if args and args.verbose:
                print(f"[!] {context}: API not enabled")
        elif "PERMISSION_DENIED" in str(e) or "accessNotConfigured" in str(e):
            if args and args.verbose:
                print(f"[!] {context}: Insufficient permissions")
        return False
    elif isinstance(e, Exception):
        if args and args.verbose:
            print(f"[!] {context}: Error occurred")
        return False
    return False

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
            print(f"[*] Successfully impersonating: {service_account_email}")
        return target_credentials
    except google.auth.exceptions.GoogleAuthError as e:
        print(f"[!] Failed to impersonate {service_account_email}: {e}")
        return None

def print_gcp_hound_banner():
    """Print the GCP-HOUND ASCII banner"""
    banner = r"""
 ██████╗  ██████╗██████╗       ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
██╔════╝ ██╔════╝██╔══██╗      ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██║  ███╗██║     ██████╔╝█████╗███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██║   ██║██║     ██╔═══╝ ╚════╝██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
╚██████╔╝╚██████╗██║           ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚═════╝  ╚═════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
"""
    print(f"\033[96m{banner}\033[0m")
    print(f"\033[97m🔐 Google Cloud Platform Security Assessment & Attack Surface Discovery\033[0m")
    print(f"\033[97m🎯 Comprehensive GCP Privilege Escalation Detection & BloodHound Integration\033[0m")
    print("═" * 79)

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
    • Access BigQuery datasets, GKE clusters, logging sinks
    • (Optional) Google Workspace Admin API for user/group enumeration

BLOODHOUND INTEGRATION:
  To enable GCP object search in BloodHound UI, run the setup script first:
    $ python3 register_gcp_nodes.py --url http://localhost:8080
    
  This registers custom GCP node types and icons (one-time setup per BloodHound instance)

Examples:
  # First authenticate with Google Cloud
  $ gcloud auth application-default login
  
  # Then run GCP analysis
  python3 gcp-hound.py                                    # Clean output
  python3 gcp-hound.py -v                                 # Verbose progress
  python3 gcp-hound.py -d                                 # Debug details
  python3 gcp-hound.py -p my-gcp-project                  # Target project
  python3 gcp-hound.py -i user@project.iam.gserviceaccount.com  # Impersonate

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
    
    args = parser.parse_args()

    # Setup logging with proper cleanup
    log_level = logging.ERROR  # Default to quiet
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

    # Suppress noisy third-party library logs unless debug mode
    if not args.debug:
        logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
        logging.getLogger('googleapiclient.discovery').setLevel(logging.ERROR)
        logging.getLogger('google.auth').setLevel(logging.ERROR)
        logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
        logging.getLogger('google.auth.transport.requests').setLevel(logging.ERROR)

    # Print banner unless quiet mode
    if not args.quiet:
        print_gcp_hound_banner()
        print()
        
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
        try:
            projects, discovery_method = discover_projects_comprehensive(creds)
        except Exception as e:
            handle_api_error(e, "Project discovery", args)
            if "Cloud Resource Manager API disabled" in str(e):
                print("[!] Cloud Resource Manager API: Access denied")
            projects = []
        
        if not projects:
            print(f"{colorize('[!] No projects discovered - cannot continue', TerminalColors.RED)}")
            return
        
        if args.verbose:
            print(f"[*] Discovered {len(projects)} projects using {discovery_method}")
        else:
            print(f"[+] Found {len(projects)} projects")

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
        try:
            project_apis = discover_apis_for_projects(creds, projects)
            capabilities, enriched_project_data = assess_enumeration_capabilities(project_apis)
            
            if args.verbose:
                enabled_apis = [k for k, v in capabilities.items() if v]
                print(f"[*] Enabled capabilities: {', '.join(enabled_apis)}")
        except Exception as e:
            handle_api_error(e, "API capability assessment", args)
            capabilities = {}

        # Early Admin Status Check with conditional logic
        try:
            admin_status = check_workspace_admin_status(creds)
            if args.verbose:
                print(f"\n{colorize('[*] Google Workspace Admin Status Check:', TerminalColors.CYAN)}")
                if admin_status['hasAdminAccess']:
                    print(f"    {colorize('✓ ADMIN ACCESS', TerminalColors.GREEN)}: {admin_status['adminLevel']}")
                    has_admin_sdk_access = True
                else:
                    print(f"    {colorize('✗ NO ADMIN ACCESS', TerminalColors.YELLOW)}")
                    has_admin_sdk_access = False
            else:
                has_admin_sdk_access = admin_status['hasAdminAccess']
        except Exception as e:
            handle_api_error(e, "Workspace admin check", args)
            has_admin_sdk_access = False
        
        print(f"\n[*] Phase 3: Resource Enumeration")
        
        # Resource collection with error handling
        sacs = []
        if capabilities.get("Service Accounts"):
            try:
                sacs = collect_service_accounts(creds, projects)
                if args.verbose:
                    print(f"[+] Found {len(sacs)} service accounts")
            except Exception as e:
                handle_api_error(e, "Service account enumeration", args)
        
        buckets = []
        if capabilities.get("Storage Buckets"):
            try:
                buckets = collect_buckets(creds, projects)
                if args.verbose and buckets:
                    for bucket in buckets[:3]:  # Show first 3
                        print(f"    - {bucket.get('name', 'unnamed')} ({bucket.get('location', 'unknown location')})")
                    if len(buckets) > 3:
                        print(f"    ... and {len(buckets) - 3} more")
            except Exception as e:
                handle_api_error(e, "Storage bucket enumeration", args)
        
        secrets = []
        if capabilities.get("Secrets"):
            try:
                secrets = collect_secrets(creds, projects)
            except Exception as e:
                handle_api_error(e, "Secret enumeration", args)
        
        instances = []
        if capabilities.get("Compute Instances"):
            try:
                instances = collect_compute_instances(creds, projects)
            except Exception as e:
                handle_api_error(e, "Compute instance enumeration", args)
        
        bigquery_datasets = []
        if capabilities.get("BigQuery"):
            try:
                bigquery_datasets = collect_bigquery_resources(creds, projects)
                if args.verbose and bigquery_datasets:
                    for ds in bigquery_datasets:
                        risk = ds.get('riskLevel', 'UNKNOWN')
                        print(f"    📊 {ds.get('name', 'unnamed')} - {risk} RISK")
            except Exception as e:
                handle_api_error(e, "BigQuery enumeration", args)
        
        gke_clusters = []
        if capabilities.get("GKE Clusters"):
            try:
                gke_clusters = collect_gke_clusters(creds, projects)
            except Exception as e:
                handle_api_error(e, "GKE enumeration", args)

        log_sinks, log_buckets, log_metrics = [], [], []
        if capabilities.get("Logging"):
            try:
                log_sinks, log_buckets, log_metrics = collect_logging_resources(creds, projects)
                if args.verbose:
                    print(f"[+] Found {len(log_sinks)} log sinks, {len(log_buckets)} log buckets, {len(log_metrics)} log metrics")
            except Exception as e:
                handle_api_error(e, "Logging enumeration", args)

        # Phase 3A: IAM collection
        if args.verbose:
            print(f"\n[*] Phase 3A: IAM Policy Enumeration")
        try:
            iam_data = collect_iam(creds, projects, args)
            outbound_permissions = analyze_cross_project_permissions(creds, user, projects)
        except Exception as e:
            handle_api_error(e, "IAM enumeration", args)
            iam_data = []
            outbound_permissions = []
        
        # Phase 3B: Folder collection  
        if args.verbose:
            print(f"\n[*] Phase 3B: Organizational Structure Enumeration")
        try:
            folders, folder_hierarchy = collect_folders(creds, [], args)
        except Exception as e:
            handle_api_error(e, "Folder enumeration", args)
            folders, folder_hierarchy = [], {}
        
        # Clean summary for non-verbose mode
        if not args.verbose:
            summary_items = []
            if sacs: summary_items.append(f"{len(sacs)} service accounts")
            if buckets: summary_items.append(f"{len(buckets)} buckets")
            if bigquery_datasets: summary_items.append(f"{len(bigquery_datasets)} datasets")
            if secrets: summary_items.append(f"{len(secrets)} secrets")
            if instances: summary_items.append(f"{len(instances)} instances")
            if gke_clusters: summary_items.append(f"{len(gke_clusters)} clusters")
            if log_sinks or log_buckets or log_metrics:
                total_logging = len(log_sinks) + len(log_buckets) + len(log_metrics)
                summary_items.append(f"{total_logging} logging resources")
            
            if summary_items:
                print(f"[+] Found: {', '.join(summary_items)}")
            else:
                print(f"[!] Limited resource access - enable APIs or use higher privileges")

        # Conditional Users/Groups enumeration
        users, groups, group_memberships = [], [], []
        if has_admin_sdk_access:
            try:
                users, groups, group_memberships = collect_users(creds, projects)
                if args.verbose:
                    print(f"[*] Found: {len(users)} users, {len(groups)} groups")
            except Exception as e:
                handle_api_error(e, "User/group enumeration", args)
        else:
            if args.verbose:
                print(f"\n{colorize('[*] Skipping Google Workspace user/group enumeration - Admin SDK access not available', TerminalColors.YELLOW)}")

        # Phase 4A: Service Account Key Analysis
        key_analysis = []
        if sacs:
            print(f"\n[*] Phase 4A: Service Account Key Access Analysis")
            try:
                key_analysis = analyze_service_account_key_access(creds, sacs, args)
                
                # Count critical findings
                critical_count = sum(1 for analysis in key_analysis if 'critical' in str(analysis).lower())
                high_count = sum(1 for analysis in key_analysis if 'high' in str(analysis).lower())
                
                if critical_count > 0:
                    print(f"🚨 Found {critical_count} CRITICAL privilege escalation opportunities")
                if high_count > 0 and args.verbose:
                    print(f"⚠️  Found {high_count} HIGH risk privilege paths")
                    
                if args.verbose:
                    print(f"[*] Analyzed key access for {len(sacs)} service accounts")
            except Exception as e:
                handle_api_error(e, "Key access analysis", args)

        # Phase 4B: Secret Access Privilege Analysis
        secret_access_analysis = []
        if secrets and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4B: Secret Access Privilege Analysis")
            try:
                secret_access_analysis = analyze_secret_access_privileges(creds, secrets, sacs)
                if args.verbose:
                    print(f"[*] Analyzed secret access for {len(secrets)} secrets")
            except Exception as e:
                handle_api_error(e, "Secret access analysis", args)

        # Phase 4C: Compute Instance Privilege Escalation Analysis
        instance_escalation_analysis = []
        if instances and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4C: Compute Instance Privilege Escalation Analysis")
            try:
                instance_escalation_analysis = analyze_instance_privilege_escalation(creds, instances, sacs)
                if args.verbose:
                    print(f"[*] Analyzed escalation for {len(instances)} instances")
            except Exception as e:
                handle_api_error(e, "Instance escalation analysis", args)

        # Phase 4D: BigQuery Access Privilege Analysis
        bigquery_access_analysis = []
        if bigquery_datasets and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4D: BigQuery Access Privilege Analysis")
            try:
                bigquery_access_analysis = analyze_bigquery_access_privileges(creds, bigquery_datasets, sacs)
                if args.verbose:
                    print(f"[*] Analyzed BigQuery access for {len(bigquery_datasets)} datasets")
            except Exception as e:
                handle_api_error(e, "BigQuery access analysis", args)

        # Phase 4E: GKE Cluster Privilege Escalation Analysis
        gke_escalation_analysis = []
        if gke_clusters and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4E: GKE Cluster Privilege Escalation Analysis")
            try:
                gke_escalation_analysis = analyze_gke_privilege_escalation(creds, gke_clusters, sacs)
                if args.verbose:
                    print(f"[*] Analyzed GKE escalation for {len(gke_clusters)} clusters")
            except Exception as e:
                handle_api_error(e, "GKE escalation analysis", args)

        # Phase 4F: Users/Groups Privilege Escalation Analysis
        users_groups_escalation = {}
        if users and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4F: Users/Groups Privilege Escalation Analysis")
            try:
                users_groups_escalation = analyze_users_groups_privilege_escalation(users, groups, group_memberships, sacs)
                if args.verbose:
                    print(f"[*] Analyzed user/group escalation for {len(users)} users")
            except Exception as e:
                handle_api_error(e, "User/group escalation analysis", args)

        logging_analysis = []
        if (log_sinks or log_buckets or log_metrics) and sacs:
            if args.verbose:
                print(f"\n[*] Phase 4G: Logging Privilege Analysis")
            try:
                logging_analysis = analyze_logging_access_privileges(
                    log_sinks, 
                    log_buckets, 
                    log_metrics, 
                    sacs
                )
                if args.verbose:
                    total_resources = len(log_sinks) + len(log_buckets) + len(log_metrics)
                    print(f"[*] Analyzed logging privileges for {total_resources} logging resources")
            except Exception as e:
                handle_api_error(e, "Logging privilege analysis", args)

        # Phase 4H: Comprehensive Privilege Escalation Analysis
        if args.verbose:
            print(f"\n[*] Phase 4H: 🚨 {colorize('COMPREHENSIVE PRIVILEGE ESCALATION ANALYSIS', TerminalColors.BOLD + TerminalColors.RED)}")
        escalation_results = []
        try:
            privesc_analyzer = GCPPrivilegeEscalationAnalyzer(creds)
            escalation_results = privesc_analyzer.analyze_all_privilege_escalation_paths(projects, sacs)
            
            if args.verbose:
                print(f"[*] Analyzed {len(projects)} projects for privilege escalation")
        except Exception as e:
            handle_api_error(e, "Privilege escalation analysis", args)
            escalation_results = []
        
        # Phase 5: Build ALL edges
        if args.verbose:
            print(f"\n[*] Phase 5: Building Complete Attack Path Graph")
        try:
            base_edges = build_edges(projects, iam_data, [], sacs, buckets, secrets, bigquery_datasets)
            key_access_edges = build_key_access_edges(sacs, key_analysis, user) if key_analysis else []
            secret_access_edges = build_secret_access_edges(secrets, secret_access_analysis, user) if secret_access_analysis else []
            compute_edges = build_compute_instance_edges(instances, instance_escalation_analysis, user) if instances else []
            #bigquery_edges = build_bigquery_edges(bigquery_datasets, bigquery_access_analysis, user) if bigquery_datasets else []
            gke_edges = build_gke_edges(gke_clusters, gke_escalation_analysis, user) if gke_clusters else []
            users_groups_edges = build_users_groups_edges(users, groups, group_memberships, users_groups_escalation, user) if users else []
            
            logging_edges = []
            if log_sinks or log_buckets or log_metrics:
                try:
                    logging_edges = build_logging_edges(
                        log_sinks,
                        log_buckets, 
                        log_metrics,
                        logging_analysis,
                        user
                    )
                except Exception as e:
                    handle_api_error(e, "Logging edge building", args)
            
            escalation_edges = []
            if escalation_results and hasattr(privesc_analyzer, 'build_escalation_edges'):
                escalation_edges = privesc_analyzer.build_escalation_edges(user)
                
            folder_edges = build_folder_edges(folders, folder_hierarchy, projects)
            
            # Include logging edges
            all_edges = base_edges + key_access_edges + secret_access_edges + compute_edges + gke_edges + users_groups_edges + logging_edges + escalation_edges + folder_edges
            #all_edges = base_edges + key_access_edges + secret_access_edges + compute_edges + bigquery_edges + gke_edges + users_groups_edges + logging_edges + escalation_edges + folder_edges
            
            if args.verbose:
                print(f"[*] Built {len(all_edges)} total attack relationships")
                if logging_edges:
                    print(f"[*] Including {len(logging_edges)} logging-specific edges")
        except Exception as e:
            handle_api_error(e, "Attack graph building", args)
            all_edges = []

        # Phase 6: Export comprehensive BloodHound data
        print(f"\n[*] Phase 6: BloodHound Export")
        
        # Create output directory
        if not os.path.exists(args.output):
            os.makedirs(args.output)
        
        try:
            output_file = export_bloodhound_json([], users, projects, groups, sacs, buckets, secrets, all_edges, creds, iam_data, log_sinks, log_buckets, log_metrics, bigquery_datasets)
        except Exception as e:
            handle_api_error(e, "BloodHound export", args)
            output_file = None
        
        # Final comprehensive summary
        total_escalation_paths = sum(len(r.get('critical_paths', [])) + len(r.get('high_risk_paths', [])) for r in escalation_results) if escalation_results else 0
        critical_edges = len([e for e in all_edges if e.get('properties', {}).get('riskLevel') == 'CRITICAL']) if all_edges else 0
        
        # Clean summary with conditional messages
        unavailable_apis = []
        if not sacs: unavailable_apis.append("Service Accounts")
        if not buckets: unavailable_apis.append("Storage Buckets")
        if not secrets: unavailable_apis.append("Secrets")
        if not instances: unavailable_apis.append("Compute Instances")
        if not bigquery_datasets: unavailable_apis.append("BigQuery")
        if not gke_clusters: unavailable_apis.append("GKE Clusters")
        
        print(f"\n" + "=" * 80)
        if unavailable_apis:
            print(f"🎯 {colorize('GCP ANALYSIS COMPLETE - LIMITED PERMISSIONS DETECTED', TerminalColors.BOLD + TerminalColors.YELLOW)}")
        else:
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
        total_logging = len(log_sinks) + len(log_buckets) + len(log_metrics)
        print(f"    Logging Resources: {total_logging}")
        if args.verbose and total_logging > 0:
            print(f"      - Log Sinks: {len(log_sinks)}")
            print(f"      - Log Buckets: {len(log_buckets)}")
            print(f"      - Log Metrics: {len(log_metrics)}")
        print(f"    Users: {len(users)}")
        print(f"    Groups: {len(groups)}")
        if args.verbose:
            print(f"    IAM Bindings: {sum(len(iam.get('bindings', [])) for iam in iam_data)}")
            print(f"    Folders: {len(folders)}")
        
        if unavailable_apis and not args.quiet:
            print()
            print(f"⚠️  {colorize('UNAVAILABLE APIS:', TerminalColors.YELLOW)}")
            print(f"    {', '.join(unavailable_apis[:3])}")  # Show only first 3
            if args.verbose:
                print(f"    Enable APIs or use higher-privilege account for comprehensive analysis")
        
        print()
        print(f"🔗 {colorize('ATTACK GRAPH:', TerminalColors.CYAN)}")
        print(f"    {colorize(f'Total BloodHound Attack Edges: {len(all_edges)}', TerminalColors.BOLD)}")
        if logging_edges:
            print(f"    {colorize(f'Logging Attack Edges: {len(logging_edges)}', TerminalColors.BOLD)}")
        if critical_edges > 0:
            print(f"    {colorize(f'🚨 CRITICAL Attack Paths: {critical_edges}', TerminalColors.RED + TerminalColors.BOLD)}")
        
        print()
        print(f"📁 {colorize('OUTPUT:', TerminalColors.CYAN)}")
        if output_file:
            print(f"    BloodHound JSON: {output_file}")
        else:
            print(f"    BloodHound export: Failed")
        
        print()
        print(f"💡 {colorize('NEXT STEPS:', TerminalColors.CYAN)}")
        if output_file:
            print(f"    1. Upload {output_file} to BloodHound")
            print(f"    2. Run queries to visualize attack paths")
            if critical_edges > 0:
                print(f"    3. Focus on CRITICAL risk findings first")
            if logging_edges:
                print(f"    4. Examine logging-based privilege escalation paths")
            print()
            print(f"    💎 {colorize('Enable GCP Search & Icons:', TerminalColors.CYAN)}")
            print(f"       python3 register_gcp_nodes.py --url http://localhost:8080")
            print(f"       (One-time setup to make GCP objects searchable in BloodHound UI)")
        else:
            print(f"    1. Check permissions and re-run with -d flag")
            print(f"    2. Enable required GCP APIs")
        
        if unavailable_apis and args.verbose:
            print(f"    • Enable missing APIs: {', '.join(unavailable_apis)}")
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
