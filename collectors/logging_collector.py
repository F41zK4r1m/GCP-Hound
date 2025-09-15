#!/usr/bin/env python3

"""
Logging Collector for GCP-Hound with Updated Logs List Fix and Debug

Enumerates log sinks, buckets, metrics and log streams with enhanced debug output
"""

import logging
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import urllib.parse


def collect_logging_resources(creds, projects, args=None):
    log_sinks = []
    log_buckets = []
    log_metrics = []

    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue

        try:
            logging_service = build('logging', 'v2', credentials=creds)

            # Enumerate traditional log sinks
            try:
                response = logging_service.sinks().list(parent=f"projects/{project_id}").execute()
                for sink in response.get('sinks', []):
                    sink_data = {
                        'type': 'log_sink',
                        'name': sink.get('name', ''),
                        'displayName': sink.get('name', ''),
                        'objectId': f'{project_id}:sink:{sink.get("name", "")}',
                        'project': project_id,
                        'destination': sink.get('destination', ''),
                        'filter': sink.get('filter', ''),
                        'description': sink.get('description', ''),
                        'disabled': sink.get('disabled', False),
                        'createTime': sink.get('createTime', ''),
                        'updateTime': sink.get('updateTime', ''),
                        'writerIdentity': sink.get('writerIdentity', ''),
                        'includeChildren': sink.get('includeChildren', False),
                        'riskLevel': analyze_sink_risk(sink),
                        'remediationPriority': 'MEDIUM'
                    }
                    log_sinks.append(sink_data)
                if args and args.verbose:
                    print(f"[+] Found {len(response.get('sinks', []))} log sinks in {project_id}")
            except HttpError as e:
                if e.status_code != 403 and args and args.verbose:
                    print(f"[!] Failed to list log sinks for project {project_id}: {e}")

            # Enumerate log buckets
            try:
                response = logging_service.projects().locations().buckets().list(parent=f"projects/{project_id}/locations/-").execute()
                for bucket in response.get('buckets', []):
                    name_parts = bucket.get('name', '').split('/')
                    display_name = name_parts[-1] if name_parts else ''
                    bucket_data = {
                        'type': 'log_bucket',
                        'name': bucket.get('name', ''),
                        'displayName': display_name,
                        'objectId': f'{project_id}:bucket:{display_name}',
                        'project': project_id,
                        'location': name_parts[3] if len(name_parts) > 3 else 'global',
                        'description': bucket.get('description', ''),
                        'createTime': bucket.get('createTime', ''),
                        'updateTime': bucket.get('updateTime', ''),
                        'retentionDays': bucket.get('retentionDays', 30),
                        'locked': bucket.get('locked', False),
                        'lifecycleState': bucket.get('lifecycleState', 'ACTIVE'),
                        'riskLevel': analyze_bucket_risk(bucket),
                        'remediationPriority': 'MEDIUM'
                    }
                    log_buckets.append(bucket_data)
                if args and args.verbose:
                    print(f"[+] Found {len(response.get('buckets', []))} log buckets in {project_id}")
            except HttpError as e:
                if e.status_code != 403 and args and args.verbose:
                    print(f"[!] Failed to list log buckets for project {project_id}: {e}")

            # Enumerate log metrics
            try:
                response = logging_service.projects().metrics().list(parent=f"projects/{project_id}").execute()
                for metric in response.get('metrics', []):
                    name_parts = metric.get('name', '').split('/')
                    display_name = name_parts[-1] if name_parts else ''
                    metric_data = {
                        'type': 'log_metric',
                        'name': metric.get('name', ''),
                        'displayName': display_name,
                        'objectId': f'{project_id}:metric:{display_name}',
                        'project': project_id,
                        'filter': metric.get('filter', ''),
                        'description': metric.get('description', ''),
                        'disabled': metric.get('disabled', False),
                        'createTime': metric.get('createTime', ''),
                        'updateTime': metric.get('updateTime', ''),
                        'riskLevel': analyze_metric_risk(metric),
                        'remediationPriority': 'MEDIUM'
                    }
                    log_metrics.append(metric_data)
                if args and args.verbose:
                    print(f"[+] Found {len(response.get('metrics', []))} log metrics in {project_id}")
            except HttpError as e:
                if e.status_code != 403 and args and args.verbose:
                    print(f"[!] Failed to list log metrics for project {project_id}: {e}")

            # Enumerate actual log streams with FIXED API call
            log_stream_count = 0
            try:
                if args and args.debug:
                    print(f"[DEBUG] About to call logs().list() for project {project_id}")

                # Add pageSize parameter to force API to return results
                response = logging_service.projects().logs().list(
                    parent=f"projects/{project_id}",
                    pageSize=1000  # Force API to return more results
                ).execute()

                if args and args.debug:
                    print(f"[DEBUG] ========== LOGS.LIST API RESPONSE ==========")
                    print(f"[DEBUG] Raw response: {response}")
                    print(f"[DEBUG] Response keys: {list(response.keys()) if isinstance(response, dict) else 'Not a dict'}")
                    print(f"[DEBUG] Number of logs returned: {len(response.get('logs', []))}")
                    print(f"[DEBUG] ===============================================")

                    # Check for alternative response keys
                    if 'resourceNames' in response:
                        print(f"[DEBUG] Found resourceNames: {response['resourceNames']}")
                    if 'logNames' in response:
                        print(f"[DEBUG] Found logNames: {response['logNames']}")

                # Check multiple possible response formats
                logs_list = response.get('logs', []) or response.get('logNames', []) or response.get('resourceNames', [])

                for log_name in logs_list:
                    # Extract and decode the log name
                    raw_log_name = log_name
                    decoded_name = urllib.parse.unquote(log_name.split('/')[-1])
                    
                    # Create safe object ID
                    safe_id = decoded_name.replace(".", "_").replace("/", "_").replace(":", "_")
                    
                    # Determine log properties
                    log_type = determine_log_type(decoded_name)
                    risk_level = analyze_log_stream_risk(decoded_name)
                    sensitivity = determine_log_sensitivity(decoded_name)
                    
                    log_stream_data = {
                        'type': 'log_stream',  # Special marker
                        'name': log_type,
                        'displayName': log_type,
                        'objectId': f'{project_id}:logstream:{log_type}',
                        'project': project_id,
                        'logType': log_type,
                        'description': f'GCP Log Stream: {decoded_name}',
                        'riskLevel': risk_level,
                        'sensitivityLevel': sensitivity,
                        'accessRequired': determine_required_permissions(decoded_name),
                        'remediationPriority': 'CRITICAL' if risk_level == 'CRITICAL' else 'HIGH' if risk_level == 'HIGH' else 'MEDIUM',
                        # Additional properties for BloodHound compatibility
                        'destination': f'stream:{log_type}',
                        'filter': f'LOG_TYPE:{log_type}',
                        'disabled': False,
                        'createTime': '',
                        'updateTime': '',
                        'writerIdentity': '',
                        'includeChildren': False
                    }
                    
                    # Add to log_sinks for backward compatibility with existing processing
                    log_sinks.append(log_stream_data)
                    log_stream_count += 1
                    
                    if args and args.debug:
                        print(f"[DEBUG] Created log stream node: {log_stream_data['objectId']}")
                
                if args and args.verbose:
                    print(f"[+] Found {log_stream_count} accessible log streams in {project_id}")
                    if log_stream_count > 0:
                        # Show examples of what was found
                        activity_logs = [s for s in log_sinks if s.get('type') == 'log_stream' and s.get('logType') == 'activity']
                        data_access_logs = [s for s in log_sinks if s.get('type') == 'log_stream' and s.get('logType') == 'data_access']
                        if activity_logs:
                            print(f"    - Activity logs: {len(activity_logs)} streams")
                        if data_access_logs:
                            print(f"    - Data access logs: {len(data_access_logs)} streams")
                    
            except HttpError as e:
                if args and args.debug:
                    print(f"[DEBUG] HttpError in logs.list: {e}")
                    print(f"[DEBUG] Status code: {e.status_code}")
                    print(f"[DEBUG] Error details: {e.error_details}")
                if e.status_code != 403 and args and args.verbose:
                    print(f"[!] Failed to list log streams for project {project_id}: {e}")
            except Exception as e:
                if args and args.debug:
                    print(f"[DEBUG] Exception in logs.list: {e}")
                    import traceback
                    traceback.print_exc()
                if args and args.verbose:
                    print(f"[!] Failed to list log streams for project {project_id}: {e}")

        except Exception as e:
            if args and args.debug:
                print(f"[DEBUG] Exception initializing logging service: {e}")
                import traceback
                traceback.print_exc()
            if args and args.verbose:
                print(f"[!] Failed to initialize logging service for project {project_id}: {e}")

    # Final summary with debug info
    if args and args.verbose:
        total_traditional = len([s for s in log_sinks if s.get('type') != 'log_stream'])
        total_streams = len([s for s in log_sinks if s.get('type') == 'log_stream'])
        print(f"[+] TOTAL: {len(log_sinks)} log sinks ({total_traditional} traditional, {total_streams} streams), {len(log_buckets)} log buckets, {len(log_metrics)} log metrics")
        
        if args.debug and total_streams > 0:
            print(f"[DEBUG] Log stream breakdown:")
            for sink in log_sinks:
                if sink.get('type') == 'log_stream':
                    print(f"[DEBUG]   - {sink['displayName']} ({sink['logType']}, {sink['riskLevel']} risk)")

    return log_sinks, log_buckets, log_metrics


# ===== Risk Analysis Helper Functions =====

def analyze_sink_risk(sink):
    """Analyze risk level of a log sink"""
    dest = sink.get('destination', '').lower()
    filt = sink.get('filter', '').lower()
    
    # Critical: External destinations with sensitive filters
    if any(d in dest for d in ['bigquery', 'pubsub', 'storage.googleapis.com']):
        if any(s in filt for s in ['audit', 'admin', 'data_access']):
            return 'CRITICAL'
    
    # High: Include children or cross-project
    if sink.get('includeChildren', False):
        return 'HIGH'
    
    # Medium: Error/warning monitoring
    if any(k in filt for k in ['error', 'warning', 'critical']):
        return 'MEDIUM'
        
    return 'LOW'


def analyze_bucket_risk(bucket):
    """Analyze risk level of a log bucket"""
    retention = bucket.get('retentionDays', 30)
    locked = bucket.get('locked', False)
    
    # Critical: Long retention without lock (data exposure risk)
    if retention > 365 and not locked:
        return 'CRITICAL'
        
    # High: Very long retention
    if retention > 90:
        return 'HIGH'
        
    # Medium: Above default retention
    if retention > 30:
        return 'MEDIUM'
        
    return 'LOW'


def analyze_metric_risk(metric):
    """Analyze risk level of a log metric"""
    filt = metric.get('filter', '').lower()
    name = metric.get('name', '').lower()
    combined = filt + ' ' + name
    
    # Critical: Security/audit monitoring
    if any(k in combined for k in ['audit', 'admin', 'security', 'privilege']):
        return 'CRITICAL'
        
    # High: Error/exception monitoring
    if any(k in combined for k in ['error', 'warning', 'exception', 'failure']):
        return 'HIGH'
        
    # Medium: Performance monitoring
    if any(k in combined for k in ['latency', 'count', 'rate', 'response_time']):
        return 'MEDIUM'
        
    return 'LOW'


def determine_log_type(log_name):
    """Determine the type of log based on its name"""
    name = log_name.lower()
    
    if 'cloudaudit.googleapis.com/activity' in name:
        return 'activity'
    elif 'cloudaudit.googleapis.com/data_access' in name:
        return 'data_access'
    elif 'cloudaudit.googleapis.com/system_event' in name:
        return 'system_event'
    elif 'cloudaudit.googleapis.com/access_transparency' in name:
        return 'access_transparency'
    elif 'audit' in name:
        return 'audit'
    elif 'error' in name or 'exception' in name:
        return 'error'
    elif 'request' in name or 'http' in name:
        return 'request'
    else:
        return 'application'


def analyze_log_stream_risk(log_name):
    """Analyze risk level of log streams based on content sensitivity"""
    name = log_name.lower()
    
    # Critical: Data access, admin activities, authentication
    if any(c in name for c in ['data_access', 'admin', 'authentication', 'access_transparency']):
        return 'CRITICAL'
    
    # High: Activity logs, audit logs, security events
    if any(h in name for h in ['activity', 'audit', 'security', 'authorization', 'iam']):
        return 'HIGH'
    
    # Medium: System events, errors, warnings
    if any(m in name for m in ['system_event', 'error', 'warning', 'failed']):
        return 'MEDIUM'
    
    return 'LOW'


def determine_log_sensitivity(log_name):
    """Determine sensitivity level of log based on data classification"""
    name = log_name.lower()
    
    # Critical: Data access, admin operations
    if any(c in name for c in ['data_access', 'admin', 'authentication']):
        return 'CRITICAL'
    
    # High: Activity monitoring, audit trails
    if any(h in name for h in ['activity', 'audit', 'security']):
        return 'HIGH'
    
    # Medium: System events, operational logs
    if any(m in name for m in ['system_event', 'request', 'warning']):
        return 'MEDIUM'
    
    return 'LOW'


def determine_required_permissions(log_name):
    """Determine required IAM permissions to access specific logs"""
    name = log_name.lower()
    
    if 'data_access' in name:
        return ['logging.privateLogEntries.list', 'logging.views.access']
    elif 'audit' in name or 'activity' in name:
        return ['logging.logEntries.list', 'logging.views.access']
    else:
        return ['logging.logEntries.list']


# ===== Privilege Analysis Functions =====

def analyze_logging_access_privileges(log_sinks, log_buckets, log_metrics, service_accounts):
    """Analyze which service accounts have access to logging resources"""
    analysis = []
    
    # Analyze log sinks (including log streams)
    for sink in log_sinks:
        sink_analysis = {
            'resource_id': sink.get('objectId'),
            'resource_type': sink.get('type'),
            'resource_name': sink.get('displayName'),
            'project': sink.get('project'),
            'privilege_paths': []
        }
        
        # Check writer identity for traditional sinks
        writer_identity = sink.get('writerIdentity', '').lower()
        if writer_identity:
            linked_sas = [sa for sa in service_accounts if sa.get('email', '').lower() in writer_identity]
            for sa in linked_sas:
                privilege = {
                    'type': 'log_sink_writer',
                    'service_account': sa.get('email'),
                    'sink_name': sink.get('displayName'),
                    'risk_level': 'HIGH',
                    'description': f"Service Account {sa.get('email')} can write to log sink {sink.get('displayName')}"
                }
                sink_analysis['privilege_paths'].append(privilege)
        
        # Check log stream access (all authenticated users can typically read logs they have permission for)
        if sink.get('type') == 'log_stream':
            privilege = {
                'type': 'log_stream_access',
                'log_name': sink.get('displayName'),
                'log_type': sink.get('logType'),
                'risk_level': sink.get('riskLevel', 'MEDIUM'),
                'sensitivity': sink.get('sensitivityLevel', 'MEDIUM'),
                'required_permissions': sink.get('accessRequired', []),
                'description': f"Access to {sink.get('logType')} log stream: {sink.get('displayName')}"
            }
            sink_analysis['privilege_paths'].append(privilege)
        
        # Only include if there are privilege paths
        if sink_analysis['privilege_paths']:
            analysis.append(sink_analysis)
    
    return analysis


def build_logging_edges(log_sinks, log_buckets, log_metrics, logging_analysis, current_user):
    """Build attack graph edges for logging privileges"""
    edges = []
    
    # Process privilege analysis results
    for analysis in logging_analysis:
        resource_id = analysis.get('resource_id')
        privilege_paths = analysis.get('privilege_paths', [])
        
        for privilege in privilege_paths:
            if privilege.get('type') == 'log_sink_writer':
                # Service account can write to log sink
                edge = {
                    'start': {'value': privilege.get('service_account')},
                    'end': {'value': resource_id},
                    'kind': 'CanWriteToLogSink',
                    'properties': {
                        'riskLevel': privilege.get('risk_level', 'HIGH'),
                        'description': privilege.get('description'),
                        'escalationMethod': 'log_sink_writer_identity'
                    }
                }
                edges.append(edge)
                
            elif privilege.get('type') == 'log_stream_access':
                # User can access log stream
                access_kind = 'CanViewSensitiveLogs' if privilege.get('risk_level') == 'CRITICAL' else 'CanAccessLogStream'
                
                edge = {
                    'start': {'value': current_user},
                    'end': {'value': resource_id},
                    'kind': access_kind,
                    'properties': {
                        'riskLevel': privilege.get('risk_level', 'MEDIUM'),
                        'description': privilege.get('description'),
                        'logType': privilege.get('log_type'),
                        'sensitivityLevel': privilege.get('sensitivity'),
                        'requiredPermissions': privilege.get('required_permissions', []),
                        'escalationMethod': 'log_stream_access'
                    }
                }
                edges.append(edge)
    
    return edges
