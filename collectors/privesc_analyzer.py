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

def check_workspace_admin_status(creds):
    """Check if current credentials have Google Workspace admin privileges."""
    admin_status = {
        'hasAdminAccess': False,
        'adminLevel': 'None',
        'error': None
    }
    
    try:
        admin_service = build('admin', 'directory_v1', credentials=creds)
        test_request = admin_service.users().list(customer='my_customer', maxResults=1)
        test_response = test_request.execute()
        
        admin_status['hasAdminAccess'] = True
        admin_status['adminLevel'] = 'Super Admin or Delegated Admin'
        
    except HttpError as e:
        if e.resp.status == 400 and 'Invalid Input' in str(e):
            admin_status['error'] = 'Invalid Input - missing domain-wide delegation'
        elif e.resp.status == 404:
            admin_status['error'] = 'Domain not found - no Google Workspace organization'
        elif e.resp.status == 403:
            admin_status['error'] = 'Access denied - insufficient admin privileges'
        else:
            admin_status['error'] = f'HTTP {e.resp.status}: {str(e)}'
    except Exception as e:
        admin_status['error'] = f'Unexpected error: {str(e)}'
    
    return admin_status

class GCPPrivilegeEscalationAnalyzer:
    """
    Comprehensive GCP privilege escalation path analyzer.
    Tests ALL known privilege escalation vectors and builds BloodHound attack paths.
    """
    
    def __init__(self, creds):
        self.creds = creds
        self.escalation_results = []
        
        # COMPLETE privilege escalation method definitions (20 methods)
        self.escalation_methods = {
            # IAM-based methods (CRITICAL)
            'iam_serviceAccountKeys_create': {
                'permission': 'iam.serviceAccountKeys.create',
                'risk': 'CRITICAL',
                'description': 'Can create service account keys - direct privilege escalation',
                'test_function': self._test_sa_key_creation
            },
            'iam_serviceAccounts_getAccessToken': {
                'permission': 'iam.serviceAccounts.getAccessToken',
                'risk': 'CRITICAL', 
                'description': 'Can generate access tokens for service accounts',
                'test_function': self._test_access_token_generation
            },
            'iam_serviceAccounts_actAs': {
                'permission': 'iam.serviceAccounts.actAs',
                'risk': 'HIGH',
                'description': 'Can impersonate service accounts',
                'test_function': self._test_service_account_impersonation
            },
            'iam_serviceAccounts_signBlob': {
                'permission': 'iam.serviceAccounts.signBlob',
                'risk': 'HIGH',
                'description': 'Can sign arbitrary data as service account',
                'test_function': self._test_blob_signing
            },
            'iam_serviceAccounts_signJwt': {
                'permission': 'iam.serviceAccounts.signJwt',
                'risk': 'HIGH',
                'description': 'Can create JWT tokens as service account',
                'test_function': self._test_jwt_signing
            },
            'iam_roles_update': {
                'permission': 'iam.roles.update',
                'risk': 'CRITICAL',
                'description': 'Can modify custom IAM roles - privilege expansion',
                'test_function': self._test_role_modification
            },
            'iam_serviceAccounts_setIamPolicy': {
                'permission': 'iam.serviceAccounts.setIamPolicy',
                'risk': 'CRITICAL',
                'description': 'Can modify service account IAM policies',
                'test_function': self._test_sa_iam_policy_modification
            },
            
            # Resource creation methods (MOST DANGEROUS)
            'deploymentmanager_deployments_create': {
                'permission': 'deploymentmanager.deployments.create',
                'risk': 'CRITICAL',
                'description': 'Can create deployments as Editor service account - MOST DANGEROUS',
                'test_function': self._test_deployment_manager
            },
            'cloudfunctions_functions_create': {
                'permission': 'cloudfunctions.functions.create',
                'risk': 'HIGH',
                'description': 'Can create cloud functions with elevated service accounts',
                'test_function': self._test_cloud_function_creation
            },
            'cloudfunctions_functions_update': {
                'permission': 'cloudfunctions.functions.update',
                'risk': 'HIGH',
                'description': 'Can update cloud functions - code modification with elevated SA',
                'test_function': self._test_cloud_function_update
            },
            'compute_instances_create': {
                'permission': 'compute.instances.create',
                'risk': 'HIGH',
                'description': 'Can create compute instances with elevated service accounts',
                'test_function': self._test_compute_instance_creation
            },
            'run_services_create': {
                'permission': 'run.services.create', 
                'risk': 'HIGH',
                'description': 'Can create Cloud Run services with elevated permissions',
                'test_function': self._test_cloud_run_creation
            },
            'cloudscheduler_jobs_create': {
                'permission': 'cloudscheduler.jobs.create',
                'risk': 'HIGH',
                'description': 'Can create scheduled jobs with elevated service accounts',
                'test_function': self._test_cloud_scheduler_creation
            },
            
            # Policy manipulation methods (CRITICAL)
            'resourcemanager_projects_setIamPolicy': {
                'permission': 'resourcemanager.projects.setIamPolicy',
                'risk': 'CRITICAL',
                'description': 'Can modify project-level IAM policies',
                'test_function': self._test_project_iam_policy_modification
            },
            'resourcemanager_organizations_setIamPolicy': {
                'permission': 'resourcemanager.organizations.setIamPolicy', 
                'risk': 'CRITICAL',
                'description': 'Can modify organization-level IAM policies',
                'test_function': self._test_org_iam_policy_modification
            },
            'resourcemanager_folders_setIamPolicy': {
                'permission': 'resourcemanager.folders.setIamPolicy',
                'risk': 'CRITICAL',
                'description': 'Can modify folder-level IAM policies',
                'test_function': self._test_folder_iam_policy_modification
            },
            'orgpolicy_policy_set': {
                'permission': 'orgpolicy.policy.set',
                'risk': 'CRITICAL',
                'description': 'Can modify organization policies - security controls bypass',
                'test_function': self._test_org_policy_modification
            },
            
            # Storage and API key methods
            'storage_hmacKeys_create': {
                'permission': 'storage.hmacKeys.create',
                'risk': 'MEDIUM',
                'description': 'Can create HMAC keys for storage access',
                'test_function': self._test_hmac_key_creation
            },
            'serviceusage_apiKeys_create': {
                'permission': 'serviceusage.apiKeys.create',
                'risk': 'MEDIUM', 
                'description': 'Can create API keys',
                'test_function': self._test_api_key_creation
            },
            'serviceusage_apiKeys_list': {
                'permission': 'serviceusage.apiKeys.list',
                'risk': 'MEDIUM',
                'description': 'Can enumerate existing API keys',
                'test_function': self._test_api_key_enumeration
            }
        }
    
    def analyze_all_privilege_escalation_paths(self, projects, service_accounts):
        """
        Comprehensive analysis of ALL privilege escalation paths.
        """
        print(f"\n{colorize('🚨 COMPREHENSIVE PRIVILEGE ESCALATION ANALYSIS', TerminalColors.RED + TerminalColors.BOLD)}")
        print(f"{colorize(f'[*] Testing {len(self.escalation_methods)} escalation methods across {len(projects)} projects...', TerminalColors.CYAN)}")
        
        # REMOVED: Admin status check (now done early in main.py)
        
        for project in projects:
            project_id = project.get('projectId')
            print(f"\n{colorize(f'[*] Analyzing project: {project_id}', TerminalColors.BLUE)}")
            
            project_results = {
                'project': project_id,
                'escalation_methods': {},
                'high_risk_paths': [],
                'critical_paths': []
            }
            
            # Test each privilege escalation method
            for method_name, method_config in self.escalation_methods.items():
                result = self._test_escalation_method(project_id, method_name, method_config, service_accounts)
                project_results['escalation_methods'][method_name] = result
                
                if result.get('can_escalate'):
                    if method_config['risk'] == 'CRITICAL':
                        project_results['critical_paths'].append(method_name)
                    elif method_config['risk'] == 'HIGH':
                        project_results['high_risk_paths'].append(method_name)
            
            self.escalation_results.append(project_results)
        
        self._print_escalation_summary()
        return self.escalation_results
    
    def _test_escalation_method(self, project_id, method_name, method_config, service_accounts):
        """Test a specific privilege escalation method."""
        try:
            return method_config['test_function'](project_id, service_accounts)
        except Exception as e:
            return {
                'can_escalate': False,
                'error': str(e),
                'method': method_name,
                'risk_level': method_config['risk']
            }
    
    # IAM-based escalation methods
    def _test_sa_key_creation(self, project_id, service_accounts):
        """Test service account key creation capabilities."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccountKeys.create']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccountKeys.create' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can create keys for: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'service_account_key_creation',
            'risk_level': 'CRITICAL'
        }
    
    def _test_access_token_generation(self, project_id, service_accounts):
        """Test access token generation capabilities."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccounts.getAccessToken']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccounts.getAccessToken' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can generate access tokens for: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'access_token_generation',
            'risk_level': 'CRITICAL'
        }
    
    def _test_service_account_impersonation(self, project_id, service_accounts):
        """Test service account impersonation capabilities."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccounts.actAs']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccounts.actAs' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW + TerminalColors.BOLD)} Can impersonate service account: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'service_account_impersonation',
            'risk_level': 'HIGH'
        }
    
    def _test_blob_signing(self, project_id, service_accounts):
        """Test blob signing capabilities."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccounts.signBlob']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccounts.signBlob' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can sign blobs as: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'blob_signing',
            'risk_level': 'HIGH'
        }
    
    def _test_jwt_signing(self, project_id, service_accounts):
        """Test JWT signing capabilities."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccounts.signJwt']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccounts.signJwt' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can sign JWTs as: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'jwt_signing',
            'risk_level': 'HIGH'
        }
    
    # Resource creation methods (MOST DANGEROUS)
    def _test_deployment_manager(self, project_id, service_accounts):
        """Test Deployment Manager privilege escalation (MOST CRITICAL)."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['deploymentmanager.deployments.create']}
            )
            test_response = test_request.execute()
            
            can_create_deployments = 'deploymentmanager.deployments.create' in test_response.get('permissions', [])
            
            if can_create_deployments:
                print(f"    {colorize('💀 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can create Deployment Manager deployments - {colorize('AUTOMATIC EDITOR ESCALATION', TerminalColors.RED)}")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Editor SA via Deployment Manager in {project_id}'],
                    'method': 'deployment_manager_escalation',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'deployment_manager_escalation'}
    
    def _test_cloud_function_creation(self, project_id, service_accounts):
        """Test Cloud Function creation with elevated SAs."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['cloudfunctions.functions.create']}
            )
            test_response = test_request.execute()
            
            can_create_functions = 'cloudfunctions.functions.create' in test_response.get('permissions', [])
            
            if can_create_functions:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW + TerminalColors.BOLD)} Can create Cloud Functions - serverless code execution")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Cloud Functions in {project_id}'],
                    'method': 'cloud_function_creation',
                    'risk_level': 'HIGH'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'cloud_function_creation'}
    
    def _test_cloud_function_update(self, project_id, service_accounts):
        """Test Cloud Function update capabilities."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['cloudfunctions.functions.update']}
            )
            test_response = test_request.execute()
            
            can_update_functions = 'cloudfunctions.functions.update' in test_response.get('permissions', [])
            
            if can_update_functions:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can update Cloud Functions - code modification")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Cloud Function updates in {project_id}'],
                    'method': 'cloud_function_update',
                    'risk_level': 'HIGH'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'cloud_function_update'}
    
    def _test_compute_instance_creation(self, project_id, service_accounts):
        """Test Compute instance creation with elevated SAs."""
        try:
            compute = build("compute", "v1", credentials=self.creds)
            test_request = compute.projects().testIamPermissions(
                project=project_id,
                body={'permissions': ['compute.instances.create']}
            )
            test_response = test_request.execute()
            
            can_create_instances = 'compute.instances.create' in test_response.get('permissions', [])
            
            if can_create_instances:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW + TerminalColors.BOLD)} Can create Compute instances with elevated SAs")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Compute instances in {project_id}'],
                    'method': 'compute_instance_creation',
                    'risk_level': 'HIGH'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'compute_instance_creation'}
    
    def _test_cloud_run_creation(self, project_id, service_accounts):
        """Test Cloud Run service creation."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['run.services.create']}
            )
            test_response = test_request.execute()
            
            can_create_services = 'run.services.create' in test_response.get('permissions', [])
            
            if can_create_services:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can create Cloud Run services")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Cloud Run services in {project_id}'],
                    'method': 'cloud_run_creation',
                    'risk_level': 'HIGH'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'cloud_run_creation'}
    
    def _test_cloud_scheduler_creation(self, project_id, service_accounts):
        """Test Cloud Scheduler job creation."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['cloudscheduler.jobs.create']}
            )
            test_response = test_request.execute()
            
            can_create_jobs = 'cloudscheduler.jobs.create' in test_response.get('permissions', [])
            
            if can_create_jobs:
                print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can create Cloud Scheduler jobs")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Cloud Scheduler jobs in {project_id}'],
                    'method': 'cloud_scheduler_creation',
                    'risk_level': 'HIGH'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'cloud_scheduler_creation'}
    
    # Policy manipulation methods
    def _test_role_modification(self, project_id, service_accounts):
        """Test custom role modification capabilities."""
        try:
            iam = build("iam", "v1", credentials=self.creds)
            test_request = iam.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['iam.roles.update']}
            )
            test_response = test_request.execute()
            
            can_update_roles = 'iam.roles.update' in test_response.get('permissions', [])
            
            if can_update_roles:
                print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can modify custom IAM roles - privilege expansion")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Custom IAM roles in {project_id}'],
                    'method': 'role_modification',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'role_modification'}
    
    def _test_project_iam_policy_modification(self, project_id, service_accounts):
        """Test project IAM policy modification."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['resourcemanager.projects.setIamPolicy']}
            )
            test_response = test_request.execute()
            
            can_set_policy = 'resourcemanager.projects.setIamPolicy' in test_response.get('permissions', [])
            
            if can_set_policy:
                print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can modify project IAM policies")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'Project IAM policy for {project_id}'],
                    'method': 'project_iam_policy_modification',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'project_iam_policy_modification'}
    
    def _test_org_iam_policy_modification(self, project_id, service_accounts):
        """Test organization IAM policy modification."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['resourcemanager.organizations.setIamPolicy']}
            )
            test_response = test_request.execute()
            
            can_set_org_policy = 'resourcemanager.organizations.setIamPolicy' in test_response.get('permissions', [])
            
            if can_set_org_policy:
                print(f"    {colorize('💀 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can modify organization IAM policies - ULTIMATE ESCALATION")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': ['Organization IAM policy'],
                    'method': 'org_iam_policy_modification',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'org_iam_policy_modification'}
    
    def _test_folder_iam_policy_modification(self, project_id, service_accounts):
        """Test folder IAM policy modification."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['resourcemanager.folders.setIamPolicy']}
            )
            test_response = test_request.execute()
            
            can_set_folder_policy = 'resourcemanager.folders.setIamPolicy' in test_response.get('permissions', [])
            
            if can_set_folder_policy:
                print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can modify folder IAM policies")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': ['Folder IAM policies'],
                    'method': 'folder_iam_policy_modification',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'folder_iam_policy_modification'}
    
    def _test_sa_iam_policy_modification(self, project_id, service_accounts):
        """Test service account IAM policy modification."""
        escalation_paths = []
        
        for sa in service_accounts:
            if sa.get('project') != project_id:
                continue
                
            sa_email = sa.get('email')
            try:
                iam = build("iam", "v1", credentials=self.creds)
                test_request = iam.projects().serviceAccounts().testIamPermissions(
                    resource=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    body={'permissions': ['iam.serviceAccounts.setIamPolicy']}
                )
                test_response = test_request.execute()
                
                if 'iam.serviceAccounts.setIamPolicy' in test_response.get('permissions', []):
                    escalation_paths.append(sa_email)
                    print(f"    {colorize('⚠ HIGH', TerminalColors.YELLOW)} Can modify IAM policy for: {colorize(sa.get('displayName', sa_email), TerminalColors.WHITE)}")
                
            except Exception:
                pass
        
        return {
            'can_escalate': len(escalation_paths) > 0,
            'escalation_targets': escalation_paths,
            'method': 'sa_iam_policy_modification',
            'risk_level': 'HIGH'
        }
    
    def _test_org_policy_modification(self, project_id, service_accounts):
        """Test organization policy modification."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['orgpolicy.policy.set']}
            )
            test_response = test_request.execute()
            
            can_set_org_policy = 'orgpolicy.policy.set' in test_response.get('permissions', [])
            
            if can_set_org_policy:
                print(f"    {colorize('🚨 CRITICAL', TerminalColors.RED + TerminalColors.BOLD)} Can modify organization policies - security bypass")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': ['Organization policies'],
                    'method': 'org_policy_modification',
                    'risk_level': 'CRITICAL'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'org_policy_modification'}
    
    # Storage and API key methods
    def _test_hmac_key_creation(self, project_id, service_accounts):
        """Test HMAC key creation."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['storage.hmacKeys.create']}
            )
            test_response = test_request.execute()
            
            can_create_hmac = 'storage.hmacKeys.create' in test_response.get('permissions', [])
            
            if can_create_hmac:
                print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} Can create HMAC keys for storage access")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'HMAC keys in {project_id}'],
                    'method': 'hmac_key_creation',
                    'risk_level': 'MEDIUM'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'hmac_key_creation'}
    
    def _test_api_key_creation(self, project_id, service_accounts):
        """Test API key creation."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['serviceusage.apiKeys.create']}
            )
            test_response = test_request.execute()
            
            can_create_api_keys = 'serviceusage.apiKeys.create' in test_response.get('permissions', [])
            
            if can_create_api_keys:
                print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} Can create API keys")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'API keys in {project_id}'],
                    'method': 'api_key_creation',
                    'risk_level': 'MEDIUM'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'api_key_creation'}
    
    def _test_api_key_enumeration(self, project_id, service_accounts):
        """Test API key enumeration."""
        try:
            crm = build("cloudresourcemanager", "v1", credentials=self.creds)
            test_request = crm.projects().testIamPermissions(
                resource=f"projects/{project_id}",
                body={'permissions': ['serviceusage.apiKeys.list']}
            )
            test_response = test_request.execute()
            
            can_list_api_keys = 'serviceusage.apiKeys.list' in test_response.get('permissions', [])
            
            if can_list_api_keys:
                print(f"    {colorize('⚠ MEDIUM', TerminalColors.YELLOW)} Can enumerate existing API keys")
                
                return {
                    'can_escalate': True,
                    'escalation_targets': [f'API key enumeration in {project_id}'],
                    'method': 'api_key_enumeration',
                    'risk_level': 'MEDIUM'
                }
        except Exception:
            pass
            
        return {'can_escalate': False, 'method': 'api_key_enumeration'}
    
    def build_escalation_edges(self, current_user):
        """
        Build BloodHound edges for all discovered privilege escalation paths.
        """
        edges = []
        
        for project_result in self.escalation_results:
            project_id = project_result['project']
            
            # Create edges for each escalation path
            for method_name, result in project_result['escalation_methods'].items():
                if result.get('can_escalate'):
                    method_config = self.escalation_methods[method_name]
                    
                    edges.append({
                        "start": {"value": f"user-{current_user}"},
                        "end": {"value": f"gcp-project-{project_id}"},
                        "kind": f"CanEscalateVia{method_name.replace('_', '').title()}",
                        "properties": {
                            "source": "privilege_escalation_analysis",
                            "riskLevel": method_config['risk'],
                            "description": method_config['description'],
                            "permission": method_config['permission'],
                            "escalationMethod": method_name,
                            "escalationTargets": result.get('escalation_targets', [])
                        }
                    })
        
        return edges
    
    def _print_escalation_summary(self):
        """Print comprehensive privilege escalation summary - FIXED COUNTING BUG."""
        # Count individual escalation targets, not just method availability per project
        total_critical_targets = 0
        total_high_targets = 0
        total_medium_targets = 0
        
        for result in self.escalation_results:
            for method_name, method_result in result['escalation_methods'].items():
                if method_result.get('can_escalate'):
                    method_config = self.escalation_methods[method_name]
                    escalation_targets = method_result.get('escalation_targets', [])
                    
                    if method_config['risk'] == 'CRITICAL':
                        total_critical_targets += len(escalation_targets) if escalation_targets else 1
                    elif method_config['risk'] == 'HIGH':
                        total_high_targets += len(escalation_targets) if escalation_targets else 1
                    elif method_config['risk'] == 'MEDIUM':
                        total_medium_targets += len(escalation_targets) if escalation_targets else 1
        
        print(f"\n{colorize('🚨 COMPREHENSIVE PRIVILEGE ESCALATION SUMMARY:', TerminalColors.RED + TerminalColors.BOLD)}")
        print(f"    {colorize('💀 CRITICAL escalation targets:', TerminalColors.RED)} {colorize(str(total_critical_targets), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ HIGH-risk escalation targets:', TerminalColors.YELLOW)} {colorize(str(total_high_targets), TerminalColors.WHITE)}")
        print(f"    {colorize('📊 MEDIUM-risk escalation targets:', TerminalColors.BLUE)} {colorize(str(total_medium_targets), TerminalColors.WHITE)}")
        
        if total_critical_targets > 0:
            print(f"\n    {colorize('⚡ IMMEDIATE PRIVILEGE ESCALATION OPPORTUNITIES:', TerminalColors.RED + TerminalColors.BOLD)}")
            for result in self.escalation_results:
                for method in result['critical_paths']:
                    method_config = self.escalation_methods[method]
                    method_result = result['escalation_methods'][method]
                    targets = method_result.get('escalation_targets', [result['project']])
                    for target in targets:
                        print(f"       {colorize('•', TerminalColors.RED)} {colorize(target, TerminalColors.WHITE)}: {colorize(method_config['description'], TerminalColors.CYAN)}")
