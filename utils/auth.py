import os
import re
import sqlite3
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as UserCredentials
import google.auth

def get_google_credentials(debug=False):
    """
    Attempts to retrieve Google Cloud credentials in order:
    1. Service account key from GCP_CREDS env var.
    2. Application Default Credentials (gcloud auth application-default login).
    3. Experimental: gcloud CLI credentials.db (active account)—handles both service accounts and user OAuth.
    Exits the process with a descriptive message if no credentials are found.
    """
    # 1. Preferred: Service account for automation (key file, no browser)
    env_path = os.getenv("GCP_CREDS")
    if env_path and os.path.exists(env_path):
        creds = service_account.Credentials.from_service_account_file(env_path)
        return creds

    # 2. Fallback: Application Default Credentials (ADC, browser login)
    try:
        creds, _ = google.auth.default()
        return creds
    except Exception:
        pass

    # 3. Experimental: Try extracting from gcloud credentials.db
    try:
        print("[!] No standard credentials found, attempting gcloud CLI credentials (EXPERIMENTAL, UNSUPPORTED)...")
        config_path = os.path.expanduser("~/.config/gcloud/configurations/config_default")
        active_account = None
        if os.path.exists(config_path):
            with open(config_path) as f:
                for line in f:
                    if line.strip().startswith("account ="):
                        active_account = line.split("=", 1)[1].strip()
                        break
        if not active_account:
            raise Exception("No active gcloud CLI account found in config_default.")

        db_path = os.path.expanduser("~/.config/gcloud/credentials.db")
        if not os.path.exists(db_path):
            raise Exception("gcloud credentials.db not found.")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials")
        found_cred = None
        debug_matches = [] # collect info for debug output
        for row in cursor.fetchall():
            account_email = str(row[0]).strip().lower()  # normalize
            active_account_compare = str(active_account).strip().lower()  # normalize
            if debug:
                print(f"[DEBUG] Comparing db account_id: '{account_email}' <-> active: '{active_account_compare}'")
            if active_account_compare == account_email:
                import json
                cred_json = json.loads(row[1])  # 'credential' JSON blob
                found_cred = cred_json
                print("[DEBUG] Match found for active account.")
                break
        conn.close()

        if not found_cred:
            raise Exception(f"No credential entry found for account {active_account}")

        # If credential is a service account, load credentials from info dict
        if found_cred.get("type") == "service_account":
            creds = service_account.Credentials.from_service_account_info(found_cred)
            print(f"[+] Loaded gcloud CLI credentials for: {active_account} (service account key from credentials.db)")
            return creds

        # If credential is OAuth2 (user login), handle refresh/access token
        refresh_token = found_cred.get("refresh_token")
        client_id = found_cred.get("client_id")
        client_secret = found_cred.get("client_secret")
        token_uri = found_cred.get("token_uri", "https://oauth2.googleapis.com/token")

        if refresh_token and client_id and client_secret:
            creds = UserCredentials(
                token=None,
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_uri=token_uri
            )
            print(f"[+] Loaded gcloud CLI credentials for: {active_account} (with refresh token)")
            return creds

        # If only access_token (rare/short-lived)
        access_token = found_cred.get("access_token")
        if access_token:
            from datetime import datetime
            expiry = None
            expiry_str = found_cred.get("token_expiry")
            if expiry_str:
                try:
                    expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    expiry = None
            creds = UserCredentials(
                token=access_token,
                refresh_token=None,
                client_id=None,
                client_secret=None,
                token_uri=token_uri,
                expiry=expiry
            )
            print(f"[+] Loaded gcloud CLI access token for: {active_account} (NO refresh token, may expire soon!)")
            return creds

        raise Exception(f"No usable refresh/access token or service account found for {active_account}")

    except Exception as e:
        print(f"[!] Experimental gcloud CLI fallback failed: {e}")

    print(
        "[!] No valid Google Cloud credentials found!\n"
        "You can authenticate with one of the following methods:\n"
        " 1. Export a service account key with:\n"
        "    export GCP_CREDS='/full/path/to/your/key.json'\n"
        " 2. Or run:\n"
        "    gcloud auth application-default login\n"
        "Then run:\n"
        "  python3 main.py"
    )
    exit(1)

def get_active_account(creds):
    """
    Returns the authenticated user/service account email if available,
    otherwise returns a generic unknown string.
    """
    if hasattr(creds, "service_account_email"):
        return creds.service_account_email
    if hasattr(creds, "client_id"):
        return getattr(creds, "client_id", "unknown/client-id")
    return "unknown/service-account"

def get_safe_output_filename(email):
    """
    Generate safe output filename based on authenticated user email.
    Takes first word of username and sanitizes it for filesystem safety.

    Examples:
     - compute@project.iam.gserviceaccount.com -> compute_gcp-bhopgraph.json
     - script@project.iam.gserviceaccount.com  -> script_gcp-bhopgraph.json
     - john.doe@example.com                   -> john_gcp-bhopgraph.json
    """
    if not email or '@' not in email:
        return "gcp-bhopgraph.json"

    username = email.split('@')[0]
    tokens = re.split(r'[^a-zA-Z0-9]', username)
    first_word = tokens[0].lower() if tokens and tokens[0] else ''
    safe_name = re.sub(r'[^a-z0-9_-]', '', first_word)
    if not safe_name:
        safe_name = "output"
    return f"{safe_name}_gcp-bhopgraph.json"
