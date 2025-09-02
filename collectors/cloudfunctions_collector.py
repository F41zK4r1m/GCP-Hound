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
    Enumerate all Cloud Functions across accessible projects.
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
            
            # List functions in all locations for this project
            request = cloudfunctions.projects().locations().functions().list(
                parent=f"projects/{project_id}/locations/-"
            )
            response = request.execute()
            project_functions = response.get('functions', [])
            
            if not project_functions:
                print(f"[~] No Cloud Functions found in {project_id}")
                continue
            
            for function in project_functions:
                # Extract function information
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
                    'riskLevel': 'UNKNOWN'
                }
                
                # Assess security risk level
                function_info = _assess_cloudfunction_risk(function_info)
                
                functions.append(function_info)
                
                # Print discovery with risk assessment
                risk_color = TerminalColors.RED if function_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if function_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                runtime = function_info['runtime']
                status = function_info['status']
                print(f"    {colorize('☁️', risk_color)} {function_info['name']} ({runtime}, {status}) - {colorize(function_info['riskLevel'] + ' RISK', risk_color)}")
            
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
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Cloud Functions access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Cloud Functions API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Cloud Functions in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Cloud Functions in {project_id}: {e}")
    
    # Final summary
    total_functions = len(functions)
    high_risk_functions = len([f for f in functions if f['riskLevel'] == 'HIGH'])
    medium_risk_functions = len([f for f in functions if f['riskLevel'] == 'MEDIUM'])
    
    print(f"\n{colorize('[+] CLOUD FUNCTIONS ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('☁️ Total Functions Discovered:', TerminalColors.BLUE)} {colorize(str(total_functions), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH-Risk Functions:', TerminalColors.RED)} {colorize(str(high_risk_functions), TerminalColors.WHITE)}")
    print(f"    {colorize('⚠ MEDIUM-Risk Functions:', TerminalColors.YELLOW)} {colorize(str(medium_risk_functions), TerminalColors.WHITE)}")
    
    return functions

def _assess_cloudfunction_risk(function_info):
    """Assess security risk level of a Cloud Function."""
    risk_factors = 0
    
    # Public HTTP trigger
    https_trigger = function_info.get('httpsTrigger', {})
    if https_trigger:
        risk_factors += 2  # HTTP functions are publicly accessible
    
    # No authentication required
    if https_trigger and not https_trigger.get('securityLevel'):
        risk_factors += 1
    
    # Default or overprivileged service account
    service_account = function_info.get('serviceAccountEmail', '')
    if not service_account or 'compute@developer.gserviceaccount.com' in service_account:
        risk_factors += 2
    
    # Environment variables (potential secrets)
    env_vars = function_info.get('environmentVariables', {})
    if len(env_vars) > 0:
        # Check for common secret patterns
        for key, value in env_vars.items():
            if any(secret_key in key.lower() for secret_key in ['password', 'secret', 'token', 'key', 'api']):
                risk_factors += 1
                break
    
    # High memory allocation (potential for abuse)
    memory_mb = function_info.get('availableMemoryMb', 0)
    if memory_mb >= 1024:  # 1GB or more
        risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 4:
        function_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 2:
        function_info['riskLevel'] = 'MEDIUM'
    else:
        function_info['riskLevel'] = 'LOW'
    
    return function_info

def build_cloudfunctions_edges(functions, current_user):
    """Build BloodHound edges for Cloud Functions."""
    edges = []
    
    for function in functions:
        function_name = function['name']
        project_id = function['project']
        function_id = f"gcp-cloudfunction-{project_id}-{function_name}"
        
        # Edge: Function belongs to project
        edges.append({
            "start": {"value": function_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "cloudfunctions_enumeration",
                "functionName": function_name,
                "runtime": function['runtime'],
                "status": function['status'],
                "riskLevel": function['riskLevel']
            }
        })
        
        # Edge: Function uses service account
        service_account = function.get('serviceAccountEmail')
        if service_account:
            sa_id = service_account.replace('@', '_').replace('.', '_')
            edges.append({
                "start": {"value": function_id},
                "end": {"value": f"gcp-sa-{sa_id}"},
                "kind": "UsesServiceAccount",
                "properties": {
                    "source": "cloudfunctions_enumeration",
                    "description": f"Cloud Function {function_name} runs as service account {service_account}"
                }
            })
        
        # Edge for high-risk functions
        if function['riskLevel'] in ['HIGH', 'MEDIUM']:
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": function_id},
                "kind": "CanAccessCloudFunction",
                "properties": {
                    "source": "cloudfunctions_enumeration",
                    "riskLevel": function['riskLevel'],
                    "description": f"Potential access to Cloud Function {function_name}",
                    "escalationMethod": "serverless_code_execution"
                }
            })
    
    return edges
