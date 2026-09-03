"""Fix resolution: NVD version-range analysis + Maven Central version search.

Resolution strategy (applied in order of increasing risk):
  A  NVD-guided same-minor   — NVD min-safe floor + latest patch in same minor
  B  Maven Central same-minor — latest patch when NVD has no floor
  C  Maven Central same-major — latest minor in the same major line
  D  Maven Central latest     — absolute latest stable release (cross-major)

OSV is not consulted. Fix discovery never stops because of missing advisory data.
"""
from typing import Optional

from .nvd import query_fix_boundary
from .maven_repo import fetch_stable_versions
from .versions import compare_maven, strip_maven_qualifier, version_sort_key

RISK_NONE = 'none'
RISK_PATCH = 'patch'
RISK_MINOR = 'minor'
RISK_MAJOR = 'major'
STATUS_NOT_AFFECTED = 'not-affected'
STATUS_NO_FIX = 'no-fix'


def _major_minor(v: str) -> tuple[int, int]:
    parts = [int(p) for p in strip_maven_qualifier(v).split('.') if p.isdigit()]
    return (parts[0] if parts else 0), (parts[1] if len(parts) > 1 else 0)


def _above(versions: list[str], current: str) -> list[str]:
    cur = strip_maven_qualifier(current)
    return [v for v in versions if compare_maven(strip_maven_qualifier(v), cur) > 0]


def _at_least(versions: list[str], floor: str) -> list[str]:
    f = strip_maven_qualifier(floor)
    return [v for v in versions if compare_maven(strip_maven_qualifier(v), f) >= 0]


def _same_minor(versions: list[str], current: str) -> list[str]:
    mm = _major_minor(current)
    return [v for v in versions if _major_minor(v) == mm]


def _same_major(versions: list[str], current: str) -> list[str]:
    maj = _major_minor(current)[0]
    return [v for v in versions if _major_minor(v)[0] == maj]


def _best(candidates: list[str]) -> Optional[str]:
    return max(candidates, key=version_sort_key) if candidates else None


def find_fix(
    cve_id: str,
    group_id: str,
    artifact_id: str,
    current_version: str,
    offline: bool = False,
) -> tuple[Optional[str], str, str]:
    """Find the safest upgrade that removes cve_id from group_id:artifact_id.

    Returns (fix_version, strategy, risk_level).
    fix_version is None only when no stable release newer than current_version
    exists in Maven Central under the same constraints.
    """
    if not current_version or not group_id or not artifact_id:
        return None, STATUS_NO_FIX, STATUS_NO_FIX

    # ── Step 1: NVD range check ──────────────────────────────────────────────
    nvd_floor: Optional[str] = None
    nvd_says_not_affected = False
    if not offline:
        nvd_floor, is_affected = query_fix_boundary(cve_id, current_version)
        if not is_affected:
            # NVD has no range covering current_version. Two reasons this happens:
            #   (a) genuinely not affected — current version is safe
            #   (b) NVD data is incomplete/stale for newer major release lines
            # The scanner already flagged this CVE as affecting this package, so
            # we cannot trust the NVD "not affected" verdict unconditionally.
            # Continue to Maven Central: if no upgrade exists above current in
            # the same major, we'll return NOT_AFFECTED. Otherwise return the
            # upgrade and let the operator decide.
            nvd_says_not_affected = True

    # ── Step 2: Maven Central stable version list ────────────────────────────
    all_versions = fetch_stable_versions(group_id, artifact_id)
    if not all_versions:
        return None, STATUS_NO_FIX, STATUS_NO_FIX

    above = _above(all_versions, current_version)
    candidates = _at_least(above, nvd_floor) if nvd_floor else above

    # ── Strategy A/B: same minor ─────────────────────────────────────────────
    patch = _best(_same_minor(candidates, current_version))
    if patch:
        strat = 'nvd+maven-same-minor' if nvd_floor else 'maven-same-minor'
        return patch, strat, RISK_PATCH

    # ── Strategy C: same major ───────────────────────────────────────────────
    minor = _best(_same_major(candidates, current_version))
    if minor:
        return minor, 'maven-same-major', RISK_MINOR

    # ── Strategy D: cross-major latest ──────────────────────────────────────
    if candidates:
        return _best(candidates), 'maven-latest', RISK_MAJOR

    # NVD floor excluded everything → relax floor, take best above current
    if nvd_floor and above:
        return _best(above), 'maven-latest-relaxed', RISK_MAJOR

    # NVD said not-affected and Maven Central has nothing newer in any branch
    if nvd_says_not_affected:
        return None, STATUS_NOT_AFFECTED, RISK_NONE

    return None, STATUS_NO_FIX, STATUS_NO_FIX
