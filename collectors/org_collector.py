from googleapiclient.discovery import build

def collect_orgs(creds):
    """
    Enumerate all GCP organizations visible to the current credentials.
    Returns a list of organization dicts.
    """
    try:
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        resp = crm.organizations().list().execute()
        orgs = resp.get('organizations', [])
        if orgs:
            print(f"[+] Found {len(orgs)} organizations:")
            for org in orgs:
                org_id = org.get("name", "unknown")
                display_name = org.get("displayName", "N/A")
                print(f"    - {org_id}: {display_name}")
        else:
            print("[~] No organizations visible (this is normal for most service accounts)")
        return orgs
    except Exception as e:
        print(f"[!] Unable to list organizations: {e}")
        return []
