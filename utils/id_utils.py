#!/usr/bin/env python3
"""
ID Normalization Utilities for GCP-Hound
Handles multiple identifier formats for BigQuery dataset IDs (public release compatibility)
"""
import re

def normalize_dataset_id(raw_id, project_fallback=None):
    """
    Normalize various BigQuery dataset ID formats into canonical internal format.
    Supports all these input formats:
        - project_id:dataset_id (Google Standard)
        - project_id.dataset_id (SQL Format)
        - project_id/dataset_id (Path Format)
        - project_id-dataset_id (Dash Format)
        - gcp-bq-dataset-project_id-dataset_id (Internal Format type)
        - projects/project_id/datasets/dataset_id (Full API Path)
        - dataset_id (with project_fallback)
    Returns: Canonical format 'gcp-bq-dataset-project-dataset' or None if invalid
    """
    if not raw_id:
        return None
    raw_id = str(raw_id).strip().lower()

    # Handle full API path format: projects/project_id/datasets/dataset_id
    api_match = re.match(r'^projects/([^/]+)/datasets/([^/]+)/?$', raw_id)
    if api_match:
        project, dataset = api_match.groups()
        return f"gcp-bq-dataset-{project}-{dataset}"

    # Handle already canonical format
    if raw_id.startswith('gcp-bq-dataset-'):
        parts = raw_id[len('gcp-bq-dataset-'):].split('-')
        if len(parts) >= 2:
            project = parts[0]
            dataset = '-'.join(parts[1:])
            return f"gcp-bq-dataset-{project}-{dataset}"

    # Handle project:dataset (Google standard)
    if ':' in raw_id:
        parts = raw_id.split(':', 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"gcp-bq-dataset-{parts[0]}-{parts[1]}"

    # Handle project.dataset (SQL format)
    if '.' in raw_id and raw_id.count('.') == 1:
        parts = raw_id.split('.', 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"gcp-bq-dataset-{parts[0]}-{parts[1]}"

    # Handle project/dataset (path format)
    if '/' in raw_id and not raw_id.startswith('http'):
        parts = raw_id.split('/', 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"gcp-bq-dataset-{parts[0]}-{parts[1]}"

    # Handle dataset_id with project fallback (must come before dash)
    if project_fallback and not any(sep in raw_id for sep in [':', '.', '/', '-']):
        return f"gcp-bq-dataset-{project_fallback.lower()}-{raw_id}"

    # Handle project-dataset (dash format)
    if '-' in raw_id and not raw_id.startswith('gcp-'):
        parts = raw_id.split('-', 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"gcp-bq-dataset-{parts[0]}-{parts[1]}"

    return None

def extract_project_and_dataset(canonical_id):
    """
    Extract project and dataset from canonical ID
    Returns: (project_id, dataset_id) or (None, None) if invalid
    """
    if not canonical_id or not canonical_id.startswith('gcp-bq-dataset-'):
        return None, None
    parts = canonical_id[len('gcp-bq-dataset-'):].split('-', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None

def generate_canonical_dataset_id(project_id, dataset_id):
    """
    Generate canonical dataset ID from components
    """
    if not project_id or not dataset_id:
        return None
    return f"gcp-bq-dataset-{project_id.lower()}-{dataset_id.lower()}"

def normalize_all_dataset_variations(raw_id, project_fallback=None):
    """
    Generate all possible variations for a dataset ID for flexible matching
    Returns: set of normalized IDs
    """
    variations = set()
    canonical = normalize_dataset_id(raw_id, project_fallback)
    if canonical:
        variations.add(canonical)
        project, dataset = extract_project_and_dataset(canonical)
        if project and dataset:
            variations.add(f"{project}:{dataset}")
            variations.add(f"{project}.{dataset}")
            variations.add(f"{project}/{dataset}")
            variations.add(f"projects/{project}/datasets/{dataset}")
    return variations

def validate_dataset_id_format(raw_id, project_fallback=None):
    """
    Validate if a dataset ID can be normalized
    Returns: (is_valid: bool, canonical_id: str, detected_format: str)
    """
    if not raw_id:
        return False, None, "empty"
    canonical = normalize_dataset_id(raw_id, project_fallback)
    if canonical:
        raw_lower = raw_id.lower()
        if raw_lower.startswith('projects/'):
            fmt = "api_path"
        elif raw_lower.startswith('gcp-bq-dataset-'):
            fmt = "canonical"
        elif ':' in raw_id:
            fmt = "standard"
        elif '.' in raw_id:
            fmt = "sql"
        elif '/' in raw_id:
            fmt = "path"
        elif '-' in raw_id:
            fmt = "dash"
        else:
            fmt = "unknown"
        return True, canonical, fmt
    return False, None, "unknown"
