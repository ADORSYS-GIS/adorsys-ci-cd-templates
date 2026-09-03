import json
import re
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class Version:
    @staticmethod
    def parse(v: str):
        parts = []
        for p in v.split('.'):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts

    @staticmethod
    def parse_maven(v: str):
        parts = []
        for p in v.split('.'):
            numeric_match = re.match(r'^(\d+)', p)
            if numeric_match:
                parts.append(int(numeric_match.group(1)))
                qualifier = p[numeric_match.end():]
                if qualifier:
                    parts.append(qualifier)
            else:
                parts.append(p)
        return parts

    @staticmethod
    def compare_maven(v1: str, v2: str) -> int:
        p1 = Version.parse_maven(v1)
        p2 = Version.parse_maven(v2)
        for a, b in zip(p1, p2):
            if isinstance(a, int) and isinstance(b, int):
                if a != b:
                    return (a > b) - (a < b)
            elif isinstance(a, str) and isinstance(b, str):
                if a != b:
                    return (a > b) - (a < b)
            elif isinstance(a, int) and isinstance(b, str):
                return -1
            else:
                return 1
        return (len(p1) > len(p2)) - (len(p1) < len(p2))


def strip_maven_qualifier(version: str) -> str:
    return re.sub(r'\.(Final|RELEASE|GA|Beta\d*|CR\d*|M\d*|RC\d*|SP\d*|redhat-\d+)$', '', version, flags=re.IGNORECASE)


def query_osv_for_fix(cve_id: str, package_name: str, group_id: str = '', artifact_id: str = '', ecosystem: str = "Maven", current_version: str = '') -> Optional[str]:
    """Query OSV API to find fixed version for a CVE.

    Tries multiple query strategies, starting with most specific:
      1. Maven group:artifact + CVE (most precise)
      2. CVE ID only (broader, but finds related fixes)

    If current_version is provided, filters out fix versions that would be
    a downgrade and picks the minimum valid upgrade (not the maximum).
    """
    osv_url = "https://api.osv.dev/v1/query"
    osv_vuln_url = "https://api.osv.dev/v1/vulns"

    queries = []

    if group_id and artifact_id:
        queries.append({
            "package": {"name": f"{group_id}:{artifact_id}", "ecosystem": "Maven"},
            "cve": cve_id
        })

    if ':' in package_name and package_name != f"{group_id}:{artifact_id}":
        queries.append({
            "package": {"name": package_name, "ecosystem": "Maven"},
            "cve": cve_id
        })

    queries.append({"cve": cve_id})

    seen_fixes = []
    specific_fixes = []

    for query in queries:
        try:
            req = Request(osv_url, data=json.dumps(query).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urlopen(req, timeout=30) as response:
                result = json.load(response)
                vulns = result.get('vulns', [])
                if not vulns:
                    continue
                for vuln in vulns:
                    for a in vuln.get('affected', []):
                        pkg_info = a.get('package', {})
                        pkg_name = pkg_info.get('name', '')
                        pkg_ecosystem = pkg_info.get('ecosystem', '')

                        matched_specific = False
                        if group_id and artifact_id:
                            osv_expected = f"{group_id}:{artifact_id}"
                            if pkg_name.lower() == osv_expected.lower():
                                matched_specific = True
                            elif pkg_name.lower() == f"{group_id}/{artifact_id}".lower():
                                matched_specific = True

                        for r in a.get('ranges', []):
                            range_type = r.get('type', '')
                            for event in r.get('events', []):
                                if 'fixed' in event:
                                    fixed = event['fixed']
                                    if matched_specific or pkg_ecosystem == 'Maven':
                                        specific_fixes.append(fixed)
                                    if pkg_ecosystem == 'Maven' or matched_specific:
                                        seen_fixes.append(fixed)

        except Exception:
            continue

    if not seen_fixes:
        try:
            req = Request(f"{osv_vuln_url}/{cve_id}", headers={'Content-Type': 'application/json'})
            with urlopen(req, timeout=30) as response:
                vuln = json.load(response)
                for a in vuln.get('affected', []):
                    pkg_info = a.get('package', {})
                    for r in a.get('ranges', []):
                        for event in r.get('events', []):
                            if 'fixed' in event:
                                seen_fixes.append(event['fixed'])
        except Exception:
            pass

    def is_valid_maven_version(v: str) -> bool:
        parts = v.split('.')
        if len(parts) < 2:
            return False
        try:
            int(parts[0])
            int(parts[1])
            return True
        except ValueError:
            return False

    all_fixes = seen_fixes if seen_fixes else []
    specific_valid = [f for f in specific_fixes if is_valid_maven_version(f)]

    if current_version:
        current_comparable = strip_maven_qualifier(current_version)
        upgrade_fixes = []
        for f in all_fixes:
            if not is_valid_maven_version(f):
                continue
            f_comparable = strip_maven_qualifier(f)
            if Version.compare_maven(f_comparable, current_comparable) >= 0:
                upgrade_fixes.append(f)
        if specific_valid:
            specific_upgrades = []
            for f in specific_valid:
                f_comparable = strip_maven_qualifier(f)
                if Version.compare_maven(f_comparable, current_comparable) >= 0:
                    specific_upgrades.append(f)
            if specific_upgrades:
                return sorted(specific_upgrades, key=Version.parse_maven)[0]
        if upgrade_fixes:
            return sorted(upgrade_fixes, key=Version.parse_maven)[0]
        return None

    if specific_valid:
        return sorted(specific_valid, key=Version.parse_maven)[0]
    if all_fixes:
        maven_fixes = [f for f in all_fixes if is_valid_maven_version(f)]
        if maven_fixes:
            return sorted(maven_fixes, key=Version.parse_maven)[0]
        return sorted(all_fixes)[0]

    return None