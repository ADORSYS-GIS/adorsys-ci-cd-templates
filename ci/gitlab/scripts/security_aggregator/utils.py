import json
from typing import Optional


def load_json_file(filepath: str) -> Optional[dict]:
    """Load a JSON file, return None if not found or invalid."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load {filepath}: {e}")
        return None