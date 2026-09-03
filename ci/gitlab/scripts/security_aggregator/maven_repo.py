"""Maven Central metadata client.

Provides fetch_stable_versions() — the complete stable release list for a
Maven artifact, fetched from maven-metadata.xml.
Used by resolver.py as the authoritative version source for fix discovery.
"""
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .versions import is_stable_version

_CENTRAL = "https://repo1.maven.org/maven2"


def fetch_stable_versions(group_id: str, artifact_id: str) -> list[str]:
    """Return all stable release versions from Maven Central for group_id:artifact_id.

    Returns an empty list when the artifact is not found or the network is
    unavailable — callers must handle this gracefully.
    """
    url = f"{_CENTRAL}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        req = Request(url, headers={'User-Agent': 'security-aggregator/2.0'})
        with urlopen(req, timeout=15) as resp:
            root = ET.fromstring(resp.read().decode('utf-8'))
    except (HTTPError, URLError, OSError) as exc:
        print(f"  Maven Central unavailable for {group_id}:{artifact_id}: {exc}")
        return []
    except ET.ParseError as exc:
        print(f"  Maven metadata parse error for {group_id}:{artifact_id}: {exc}")
        return []

    return [
        v.text.strip()
        for v in root.iter('version')
        if v.text and is_stable_version(v.text.strip())
    ]