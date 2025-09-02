import os
import re
from google.oauth2 import service_account

def get_google_credentials():
    # Only use GOOGLE_APPLICATION_CREDENTIALS for loading creds (most reliable)
    env_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path and os.path.exists(env_path):
        creds = service_account.Credentials.from_service_account_file(env_path)
        return creds
    print(
        "[!] No valid Google Cloud credentials found!\n"
        "Please set the environment variable GOOGLE_APPLICATION_CREDENTIALS to your service account key file:\n"
        "    export GOOGLE_APPLICATION_CREDENTIALS='/full/path/to/your/cred.json'\n"
        "and then run:\n"
        "    python3 main.py"
    )
    exit(1)

def get_active_account(creds):
    if hasattr(creds, "service_account_email"):
        return creds.service_account_email
    return "unknown/service-account"

def get_safe_output_filename(email):
    """
    Generate safe output filename based on authenticated user email.
    Takes first word of username and sanitizes it for filesystem safety.
    
    Examples:
    - compute@project.iam.gserviceaccount.com → compute_gcp-bhopgraph.json
    - script@project.iam.gserviceaccount.com → script_gcp-bhopgraph.json
    - john.doe@example.com → john_gcp-bhopgraph.json
    """
    if not email or '@' not in email:
        return "gcp-bhopgraph.json"
    
    # Extract username part before @
    username = email.split('@')[0]
    
    # Split by non-alphanumeric characters and get first word
    tokens = re.split(r'[^a-zA-Z0-9]', username)
    first_word = tokens[0].lower() if tokens and tokens[0] else ''
    
    # Sanitize for safe filesystem name (keep only alphanumeric, underscore, hyphen)
    safe_name = re.sub(r'[^a-z0-9_-]', '', first_word)
    
    # Fallback if username becomes empty after sanitization
    if not safe_name:
        safe_name = "output"
    
    return f"{safe_name}_gcp-bhopgraph.json"
