"""NVD API v2.0 client for CVE version-range data.

Used to determine:
  - Whether the project's current version falls inside a known vulnerable range.
  - The versionEndExcluding boundary (minimum safe version) for that range.

Set NVD_API_KEY in CI environment for higher rate limits (>5 req/30 s).
OSV is not consulted — NVD is the authoritative CVE source for this pipeline.
"""
import json
import os
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .versions import compare_maven, strip_maven_qualifier

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_KEY = os.environ.get('NVD_API_KEY', '')


def _headers() -> dict:
    h = {'Accept': 'application/json', 'User-Agent': 'security-aggregator/2.0'}
    if _API_KEY:
        h['apiKey'] = _API_KEY
    return h


def fetch_cve(cve_id: str) -> Optional[dict]:
    """Return the NVD CVE object for cve_id, or None on failure."""
    try:
        req = Request(f"{_NVD_BASE}?cveId={cve_id}", headers=_headers())
        with urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        vulns = data.get('vulnerabilities', [])
        return vulns[0].get('cve') if vulns else None
    except (HTTPError, URLError, OSError) as exc:
        print(f"  NVD unavailable for {cve_id}: {exc}")
        return None


def _extract_ranges(cve_data: dict) -> list[dict]:
    """Return CPE-based vulnerable version ranges from NVD CVE data."""
    ranges = []
    for cfg in cve_data.get('configurations', []):
        for node in cfg.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if not match.get('vulnerable', False):
                    continue
                entry = {
                    'si': match.get('versionStartIncluding', ''),
                    'sx': match.get('versionStartExcluding', ''),
                    'ei': match.get('versionEndIncluding', ''),
                    'ex': match.get('versionEndExcluding', ''),
                }
                if any(entry.values()):
                    ranges.append(entry)
    return ranges


def _in_range(version: str, r: dict) -> bool:
    v = strip_maven_qualifier(version)
    if r['si'] and compare_maven(v, strip_maven_qualifier(r['si'])) < 0:
        return False
    if r['sx'] and compare_maven(v, strip_maven_qualifier(r['sx'])) <= 0:
        return False
    if r['ei'] and compare_maven(v, strip_maven_qualifier(r['ei'])) > 0:
        return False
    if r['ex'] and compare_maven(v, strip_maven_qualifier(r['ex'])) >= 0:
        return False
    return True


def query_fix_boundary(cve_id: str, current_version: str) -> tuple[Optional[str], bool]:
    """Return (min_safe_version, is_affected) for current_version.

    is_affected=False  → current_version is outside all NVD affected ranges.
    min_safe_version   → versionEndExcluding for the matching range, or None
                         when NVD has no upper bound or is unreachable.

    When NVD is unreachable, returns (None, True) so Maven Central search proceeds.
    """
    cve_data = fetch_cve(cve_id)
    if cve_data is None:
        return None, True           # NVD down — proceed optimistically

    ranges = _extract_ranges(cve_data)
    if not ranges:
        return None, True           # No CPE version data — proceed

    for r in ranges:
        if _in_range(current_version, r):
            return r['ex'] or None, True

    return None, False              # Not in any affected range
