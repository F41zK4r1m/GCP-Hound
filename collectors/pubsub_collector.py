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

def collect_pubsub_resources(creds, projects):
    """
    Enumerate all Pub/Sub topics and subscriptions across accessible projects.
    Returns topics and subscriptions with security analysis.
    """
    topics = []
    subscriptions = []
    
    print(f"\n{colorize('[*] ENUMERATING PUB/SUB TOPICS AND SUBSCRIPTIONS...', TerminalColors.CYAN)}")
    
    for project in projects:
        project_id = project.get('projectId')
        if not project_id:
            continue
            
        try:
            # Build Pub/Sub API client
            pubsub = build("pubsub", "v1", credentials=creds)
            
            # List topics
            try:
                topics_request = pubsub.projects().topics().list(project=f"projects/{project_id}")
                topics_response = topics_request.execute()
                project_topics = topics_response.get('topics', [])
                
                for topic in project_topics:
                    topic_info = {
                        'name': topic.get('name', '').split('/')[-1],
                        'fullName': topic.get('name'),
                        'project': project_id,
                        'projectName': project.get('name', project_id),
                        'labels': topic.get('labels', {}),
                        'messageStoragePolicy': topic.get('messageStoragePolicy', {}),
                        'riskLevel': 'LOW'
                    }
                    
                    topics.append(topic_info)
                    print(f"    {colorize('📨', TerminalColors.BLUE)} Topic: {topic_info['name']}")
                    
            except HttpError as e:
                if e.resp.status != 403:
                    print(f"    {colorize('!', TerminalColors.YELLOW)} Error listing topics: {e}")
            
            # List subscriptions
            try:
                subs_request = pubsub.projects().subscriptions().list(project=f"projects/{project_id}")
                subs_response = subs_request.execute()
                project_subscriptions = subs_response.get('subscriptions', [])
                
                for subscription in project_subscriptions:
                    sub_info = {
                        'name': subscription.get('name', '').split('/')[-1],
                        'fullName': subscription.get('name'),
                        'project': project_id,
                        'projectName': project.get('name', project_id),
                        'topic': subscription.get('topic'),
                        'pushConfig': subscription.get('pushConfig', {}),
                        'ackDeadlineSeconds': subscription.get('ackDeadlineSeconds'),
                        'retainAckedMessages': subscription.get('retainAckedMessages', False),
                        'messageRetentionDuration': subscription.get('messageRetentionDuration'),
                        'labels': subscription.get('labels', {}),
                        'riskLevel': 'UNKNOWN'
                    }
                    
                    # Assess subscription risk
                    sub_info = _assess_subscription_risk(sub_info)
                    
                    subscriptions.append(sub_info)
                    risk_color = TerminalColors.RED if sub_info['riskLevel'] == 'HIGH' else TerminalColors.YELLOW if sub_info['riskLevel'] == 'MEDIUM' else TerminalColors.GREEN
                    print(f"    {colorize('📥', risk_color)} Subscription: {sub_info['name']} - {colorize(sub_info['riskLevel'] + ' RISK', risk_color)}")
                    
            except HttpError as e:
                if e.resp.status != 403:
                    print(f"    {colorize('!', TerminalColors.YELLOW)} Error listing subscriptions: {e}")
            
            project_total = len([t for t in topics if t['project'] == project_id]) + len([s for s in subscriptions if s['project'] == project_id])
            if project_total > 0:
                print(f"[+] Found {colorize(str(len([t for t in topics if t['project'] == project_id])), TerminalColors.WHITE)} topics and {colorize(str(len([s for s in subscriptions if s['project'] == project_id])), TerminalColors.WHITE)} subscriptions in {colorize(project_id, TerminalColors.CYAN)}")
            else:
                print(f"[~] No Pub/Sub resources found in {project_id}")
                
        except HttpError as e:
            error_code = e.resp.status
            if error_code == 403:
                print(f"[!] No Pub/Sub access for project {project_id}")
            elif error_code == 404:
                print(f"[!] Pub/Sub API not enabled for project {project_id}")
            else:
                print(f"[!] HTTP {error_code} error accessing Pub/Sub in {project_id}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error accessing Pub/Sub in {project_id}: {e}")
    
    # Final summary
    total_topics = len(topics)
    total_subscriptions = len(subscriptions)
    high_risk_subs = len([s for s in subscriptions if s['riskLevel'] == 'HIGH'])
    
    print(f"\n{colorize('[+] PUB/SUB ANALYSIS SUMMARY:', TerminalColors.CYAN + TerminalColors.BOLD)}")
    print(f"    {colorize('📨 Total Topics Discovered:', TerminalColors.BLUE)} {colorize(str(total_topics), TerminalColors.WHITE)}")
    print(f"    {colorize('📥 Total Subscriptions Discovered:', TerminalColors.BLUE)} {colorize(str(total_subscriptions), TerminalColors.WHITE)}")
    print(f"    {colorize('🚨 HIGH-Risk Subscriptions:', TerminalColors.RED)} {colorize(str(high_risk_subs), TerminalColors.WHITE)}")
    
    return topics, subscriptions

def _assess_subscription_risk(sub_info):
    """Assess security risk level of a Pub/Sub subscription."""
    risk_factors = 0
    push_config = sub_info.get('pushConfig', {})
    
    # Push endpoint configured (external access)
    if push_config.get('pushEndpoint'):
        risk_factors += 1
        
        # HTTPS endpoint
        endpoint = push_config.get('pushEndpoint', '')
        if not endpoint.startswith('https://'):
            risk_factors += 2  # HTTP endpoint is insecure
    
    # No authentication on push endpoint
    if push_config.get('pushEndpoint') and not push_config.get('oidcToken') and not push_config.get('attributes'):
        risk_factors += 1
    
    # Long message retention
    retention = sub_info.get('messageRetentionDuration', '0s')
    if 'days' in retention or int(retention.replace('s', '')) > 86400:  # More than 1 day
        risk_factors += 1
    
    # Assess overall risk
    if risk_factors >= 3:
        sub_info['riskLevel'] = 'HIGH'
    elif risk_factors >= 1:
        sub_info['riskLevel'] = 'MEDIUM'
    else:
        sub_info['riskLevel'] = 'LOW'
    
    return sub_info

def build_pubsub_edges(topics, subscriptions, current_user):
    """Build BloodHound edges for Pub/Sub resources."""
    edges = []
    
    # Edges for topics
    for topic in topics:
        topic_name = topic['name']
        project_id = topic['project']
        topic_id = f"gcp-pubsub-topic-{project_id}-{topic_name}"
        
        # Edge: Topic belongs to project
        edges.append({
            "start": {"value": topic_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "pubsub_enumeration",
                "topicName": topic_name,
                "resourceType": "topic"
            }
        })
    
    # Edges for subscriptions
    for subscription in subscriptions:
        sub_name = subscription['name']
        project_id = subscription['project']
        sub_id = f"gcp-pubsub-subscription-{project_id}-{sub_name}"
        
        # Edge: Subscription belongs to project
        edges.append({
            "start": {"value": sub_id},
            "end": {"value": f"gcp-project-{project_id}"},
            "kind": "BelongsTo",
            "properties": {
                "source": "pubsub_enumeration",
                "subscriptionName": sub_name,
                "riskLevel": subscription['riskLevel'],
                "resourceType": "subscription"
            }
        })
        
        # Edge: Subscription subscribes to topic
        topic_name = subscription.get('topic', '').split('/')[-1]
        if topic_name:
            topic_id = f"gcp-pubsub-topic-{project_id}-{topic_name}"
            edges.append({
                "start": {"value": sub_id},
                "end": {"value": topic_id},
                "kind": "SubscribesTo",
                "properties": {
                    "source": "pubsub_enumeration",
                    "description": f"Subscription {sub_name} subscribes to topic {topic_name}"
                }
            })
        
        # Edge for high-risk subscriptions
        if subscription['riskLevel'] in ['HIGH', 'MEDIUM']:
            edges.append({
                "start": {"value": f"user-{current_user}"},
                "end": {"value": sub_id},
                "kind": "CanAccessPubSub",
                "properties": {
                    "source": "pubsub_enumeration",
                    "riskLevel": subscription['riskLevel'],
                    "description": f"Potential access to Pub/Sub subscription {sub_name}",
                    "escalationMethod": "message_queue_access"
                }
            })
    
    return edges
