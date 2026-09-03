"""Maven version comparison utilities.

Shared by nvd.py, resolver.py, maven_repo.py, and maven_fixer.py.
Replaces the Version class that was embedded in osv.py (now removed).
"""
import re


def strip_maven_qualifier(version: str) -> str:
    """Remove Maven release qualifiers (.Final, .RELEASE, .GA, etc.)."""
    return re.sub(
        r'\.(Final|RELEASE|GA|Beta\d*|CR\d*|M\d*|RC\d*|SP\d*|redhat-\d+)$',
        '', version, flags=re.IGNORECASE,
    )


def _parse(v: str) -> list:
    parts = []
    for p in v.split('.'):
        m = re.match(r'^(\d+)', p)
        if m:
            parts.append(int(m.group(1)))
            q = p[m.end():]
            if q:
                parts.append(q)
        else:
            parts.append(p)
    return parts


def compare_maven(v1: str, v2: str) -> int:
    """Compare two Maven version strings. Returns -1, 0, or 1."""
    p1, p2 = _parse(v1), _parse(v2)
    for a, b in zip(p1, p2):
        if isinstance(a, int) and isinstance(b, int):
            if a != b:
                return (a > b) - (a < b)
        elif isinstance(a, str) and isinstance(b, str):
            if a != b:
                return (a > b) - (a < b)
        elif isinstance(a, int):
            return -1
        else:
            return 1
    return (len(p1) > len(p2)) - (len(p1) < len(p2))


def is_downgrade(current: str, proposed: str) -> bool:
    """Return True if proposed is strictly older than current."""
    c = [int(x) for x in strip_maven_qualifier(current).split('.') if x.isdigit()]
    p = [int(x) for x in strip_maven_qualifier(proposed).split('.') if x.isdigit()]
    n = max(len(c), len(p), 1)
    return (p + [0] * n)[:n] < (c + [0] * n)[:n]


def is_stable_version(version: str) -> bool:
    """Return True for stable releases; False for snapshots, alphas, RCs, etc."""
    v = version.lower()
    return not any(q in v for q in (
        'snapshot', 'alpha', 'beta', '-m1', '-m2', '-m3',
        '-rc', '-cr', 'dev', '-pr', 'preview',
    ))


def version_sort_key(v: str) -> list:
    """Ascending sort key for Maven version strings."""
    return [int(p) for p in strip_maven_qualifier(v).split('.') if p.isdigit()]
