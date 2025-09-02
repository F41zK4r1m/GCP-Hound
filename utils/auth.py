import os
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
