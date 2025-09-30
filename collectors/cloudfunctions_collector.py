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

def collect_cloud_functions(creds, projects):
    """
    Enumerate all Cloud Functions across accessible projects with pagination support.
    Returns a list of function dicts with security analysis.
    """
    functions = []
    
    print(f"\n{colorize('[*] ENUMERATING CLOUD FUNCTIONS...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Cloud Functions API client
            cloudfunctions = build("cloudfunctions", "v1", credentials=creds)
            
            # List functions in all locations for this project with pagination
            request = cloudfunctions.projects().locations().functions().list(
                parent=f"projects/{project_id}/locations/-"
            )
            
            # Add pagination loop to existing logic
            project_functions = []
            while request is not None:
                try:
                    response = request.execute()
                    page_functions = response.get('functions', [])
                    project_functions.extend(page_functions)
                    
                    # Get next page
                    request = cloudfunctions.projects().locations().functions().list_next(request, response)
                    
                except HttpError as e:
                    # If we get SERVICE_DISABLED during pagination, break and handle gracefully
                    if any(keyword in str(e) for keyword in ['SERVICE_DISABLED', 'API has not been used', 'not enabled']):
                        print(f"[!] Cloud Functions API not enabled for project {project_id}")
                        project_functions = []  # Clear any partial results
                        break
                    else:
                        raise  # Re-raise other HTTP errors
            
            if not project_functions:
                print(f"[~] No Cloud Functions found in {project_id}")
                continue
            
            # Process functions with enhanced metadata
            for function in project_functions:
                # Extract function information with additional security context
                function_info = {
                    'name': function.get('name', '').split('/')[-1],
                    'fullName': function.get('name'),
                    'project': project_id,
                    'projectName': project.get('name', project_id),
                    'sourceArchiveUrl': function.get('sourceArchiveUrl'),
                    'sourceRepository': function.get('sourceRepository', {}),
                    'httpsTrigger': function.get('httpsTrigger', {}),
                    'eventTrigger': function.get('eventTrigger', {}),
                    'status': function.get('status'),
                    'entryPoint': function.get('entryPoint'),
                    'runtime': function.get('runtime'),
                    'timeout': function.get('timeout'),
                    'availableMemoryMb': function.get('availableMemoryMb'),
                    'serviceAccountEmail': function.get('serviceAccountEmail'),
                    'updateTime': function.get('updateTime'),
                    'versionId': function.get('versionId'),
                    'labels': function.get('labels', {}),
                    'environmentVariables': function.get('environmentVariables', {}),
                    # Enhanced metadata
                    'region': function.get('name', '').split('/')[-3] if len(function.get('name', '').split('/')) >= 3 else 'unknown',
                    'buildId': function.get('buildId'),
                    'riskLevel': 'UNKNOWN'
                }
                
                # Assess security risk level with enhanced analysis
                function_info = assess_cloudfunction_risk_enhanced(function_info)
                
                functions.append(function_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if function_info['riskLevel'] == 'HIGH' else \
                            TerminalColors.YELLOW if function_info['riskLevel'] == 'MEDIUM' else \
                            TerminalColors.GREEN
                runtime = function_info['runtime']
                status = function_info['status']
                region = function_info['region']
                print(f"    {colorize('☁️', risk_color)} {function_info['name']} ({runtime}, {status}, {region}) - {colorize(function_info['riskLevel'] + ' RISK', risk_color)}")
            
            # Enhanced project summary
            if project_functions:
                high_risk = len([f for f in functions if f.get('project') == project_id and f['riskLevel'] == 'HIGH'])
                medium_risk = len([f for f in functions if f.get('project') == project_id and f['riskLevel'] == 'MEDIUM'])
                total_in_project = len([f for f in functions if f.get('project') == project_id])
                print(f"[+] Found {colorize(str(total_in_project), TerminalColors.WHITE)} Cloud Functions in {colorize(project_id, TerminalColors.CYAN)}")
                if high_risk > 0:
                    print(f"    {colorize('🚨', TerminalColors.RED)} {high_risk} HIGH-risk functions")
                if medium_risk > 0:
                    print(f"    {colorize('⚠', TerminalColors.YELLOW)} {medium_risk} MEDIUM-risk functions")
                
        except HttpError as e:
            error_code = e.resp.status if hasattr(e, 'resp') else 'unknown'
            if error_code == 403:
                print(f"[!] No Cloud Functions access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Cloud Functions API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Cloud Functions in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Cloud Functions in {project_id}: {e}")
    
    # Enhanced final summary
    total_functions = len(functions)
    high_risk_functions = len([f for f in functions if f['riskLevel'] == 'HIGH'])
    medium_risk_functions = len([f for f in functions if f['riskLevel'] == 'MEDIUM'])
    
    if total_functions > 0:  # Only show summary if functions exist
        print(f"\n{colorize('[+] CLOUD FUNCTIONS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
        print(f"    {colorize('☁️ Total Functions Discovered:', TerminalColors.BLUE)} {colorize(str(total_functions), TerminalColors.WHITE)}")
        print(f"    {colorize('🚨 HIGH-Risk Functions:', TerminalColors.RED)} {colorize(str(high_risk_functions), TerminalColors.WHITE)}")
        print(f"    {colorize('⚠ MEDIUM-Risk Functions:', TerminalColors.YELLOW)} {colorize(str(medium_risk_functions), TerminalColors.WHITE)}")
    
    return functions

def assess_cloudfunction_risk_enhanced(function_info):
    """
    Enhanced security risk assessment for Cloud Functions with comprehensive analysis.
    
    Args:
        function_info: Function information dictionary
        
    Returns:
        Updated function_info with riskLevel set
    """
    risk_factors = 0
    
    # Public HTTP trigger analysis
    https_trigger = function_info.get('httpsTrigger', {})
    if https_trigger:
        risk_factors += 2  # HTTP functions are publicly accessible
        
        # Enhanced security level analysis
        security_level = https_trigger.get('securityLevel', '')
        if not security_level or security_level == 'SECURE_ALWAYS':
            # SECURE_ALWAYS allows unauthenticated access
            risk_factors += 1
        elif security_level == 'SECURE_OPTIONAL':
            # Both HTTP and HTTPS allowed - less secure
            risk_factors += 1
    
    # Service account analysis with enhanced detection
    service_account = function_info.get('serviceAccountEmail', '')
    if not service_account:
        risk_factors += 2  # No explicit SA means default Compute SA
    elif 'compute@developer.gserviceaccount.com' in service_account:
        risk_factors += 2  # Default Compute SA is overprivileged
    elif service_account.endswith('@appspot.gserviceaccount.com'):
        risk_factors += 1  # App Engine default SA - also overprivileged
    
    # Environment variables security analysis
    env_vars = function_info.get('environmentVariables', {})
    if len(env_vars) > 0:
        secret_patterns = ['password', 'secret', 'token', 'key', 'api', 'auth', 'credential']
        for key, value in env_vars.items():
            if any(pattern in key.lower() for pattern in secret_patterns):
                risk_factors += 1
                break
        
        # Too many environment variables might indicate secrets
        if len(env_vars) > 10:
            risk_factors += 1
    
    # Resource allocation analysis
    memory_mb = function_info.get('availableMemoryMb', 0)
    if memory_mb >= 2048:  # 2GB or more
        risk_factors += 2  # Very high resource allocation
    elif memory_mb >= 1024:  # 1GB or more
        risk_factors += 1  # High resource allocation
    
    # Timeout analysis
    timeout = function_info.get('timeout', '')
    if timeout:
        # Parse timeout (format: "540s")
        try:
            timeout_seconds = int(timeout.replace('s', ''))
            if timeout_seconds >= 300:  # 5 minutes or more
                risk_factors += 1  # Long-running functions are riskier
        except (ValueError, AttributeError):
            pass
    
    # Runtime analysis
    runtime = function_info.get('runtime', '')
    if runtime:
        # Older runtimes might have security vulnerabilities
        if any(old_runtime in runtime.lower() for old_runtime in ['python37', 'nodejs8', 'nodejs10', 'go111']):
            risk_factors += 1
    
    # Event trigger analysis
    event_trigger = function_info.get('eventTrigger', {})
    if event_trigger:
        event_type = event_trigger.get('eventType', '')
        # Some event types are higher risk
        if 'storage' in event_type or 'pubsub' in event_type:
            # These can be triggered by external data
            risk_factors += 1
    
    # Enhanced risk assessment with more granular levels
    if risk_factors >= 6:
        function_info['riskLevel'] = 'CRITICAL'
    elif risk_factors >= 4:
        function_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        function_info['riskLevel'] = 'MEDIUM'
    else:
        function_info['riskLevel'] = 'LOW'
    
    return function_info

# Keeping existing _assess_cloudfunction_risk for backward compatibility
def _assess_cloudfunction_risk(function_info):
    """Legacy risk assessment function - kept for backward compatibility"""
    return assess_cloudfunction_risk_enhanced(function_info)

def build_cloudfunctions_edges(functions, current_user):
    """
    Build enhanced BloodHound edges for Cloud Functions with additional metadata.
    """
    edges = []
    
    for function in functions:
        function_name = function['name']
        project_id = function['project']
        region = function.get('region', 'unknown')
        function_id = f"gcp-cloudfunction-{project_id}-{region}-{function_name}"
        
        # Enhanced edge: Function belongs to project
        edges.append({
            "start": {"value": function_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "cloudfunctions_enumeration",
                "functionName": function_name,
                "runtime": function['runtime'],
                "status": function['status'],
                "region": region,
                "riskLevel": function['riskLevel'],
                "memoryMb": function.get('availableMemoryMb', 0),
                "timeout": function.get('timeout', ''),
                "hasHttpTrigger": bool(function.get('httpsTrigger')),
                "hasEventTrigger": bool(function.get('eventTrigger'))
            }
        })
        
        # Enhanced edge: Function uses service account
        service_account = function.get('serviceAccountEmail')
        if service_account:
            sa_id = service_account.replace('@', '_').replace('.', '_')
            edges.append({
                "start": {"value": function_id},
                "end": {"value": f"gcp-sa-{sa_id}"},
                "kind": "UsesServiceAccount",
                "properties": {
                    "source": "cloudfunctions_enumeration",
                    "description": f"Cloud Function {function_name} runs as service account {service_account}",
                    "isDefaultComputeSA": 'compute@developer.gserviceaccount.com' in service_account,
                    "functionRuntime": function['runtime']
                }
            })
        
        # Enhanced edge for high-risk functions
        if function['riskLevel'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": function_id},
                "kind": "CanAccessCloudFunction",
                "properties": {
                    "source": "cloudfunctions_enumeration",
                    "riskLevel": function['riskLevel'],
                    "description": f"Potential access to Cloud Function {function_name}",
                    "escalationMethod": "serverless_code_execution",
                    "isPublicHttpFunction": bool(function.get('httpsTrigger')),
                    "runtime": function['runtime'],
                    "region": region
                }
            })
    
    return edges
