"""Maven version-property and dependencyManagement helpers.

Extracted from maven_fixer.py so each module stays under 200 lines.
Used by apply.py as the last-resort strategy when no explicit <version> or
${property} reference is found for a vulnerable dependency.
"""
import re
from typing import Optional

from .versions import is_downgrade


def _heuristic_prop_names(group_id: str, artifact_id: str) -> list[str]:
    """Generate candidate Maven property names for group_id:artifact_id."""
    short = group_id.split('.')[-1] if '.' in group_id else group_id
    names = []
    for base in (artifact_id, short, f"{short}-{artifact_id}"):
        for suffix in ('.version', '-version', '.Version'):
            names.append(f"{base}{suffix}")
    for prefix in ('version.', 'version-'):
        names.append(f"{prefix}{artifact_id}")
        names.append(f"{prefix}{short}")
    stripped = re.sub(r'-(core|api|client|server|common|utils|base|all)$', '', artifact_id)
    if stripped != artifact_id:
        for suffix in ('.version', '-version'):
            names.append(f"{stripped}{suffix}")
    return names


def find_version_property(
    pom_files: list[str],
    group_id: str,
    artifact_id: str,
) -> tuple[Optional[str], Optional[str]]:
    """Find a Maven property controlling the version of group_id:artifact_id.

    Searches pom.xml files for properties matching common naming conventions.
    Returns (property_name, pom_path) or (None, None).
    """
    candidates = _heuristic_prop_names(group_id, artifact_id)
    seen: set = set()
    for pom_path in pom_files:
        try:
            with open(pom_path, encoding='utf-8') as f:
                content = f.read()
        except OSError:
            continue
        m = re.search(r'<properties>(.*?)</properties>', content, re.DOTALL)
        if not m:
            continue
        block = m.group(1)
        for name in candidates:
            if name in seen:
                continue
            if re.search(rf'<{re.escape(name)}>([^<]+)</{re.escape(name)}>', block):
                return name, pom_path
    return None, None


def add_to_dependency_management(
    pom_path: str,
    group_id: str,
    artifact_id: str,
    version: str,
    cve_ids: list[str],
    current_version: str = '',
) -> bool:
    """Insert a version pin into <dependencyManagement> as a last resort.

    Creates the section when absent. Skips if a newer version is already
    managed. Returns True when the file was modified.
    """
    try:
        with open(pom_path, encoding='utf-8') as f:
            content = f.read()

        existing = re.search(
            rf'<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*'
            rf'<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>',
            content,
        )
        if existing:
            ver_m = re.search(
                r'<version>\s*([^<]+)\s*</version>',
                content[existing.start():existing.start() + 500],
            )
            if ver_m:
                ev = ver_m.group(1).strip()
                if not ev.startswith('${') and is_downgrade(ev, version):
                    print(f"  SKIP depMgmt {group_id}:{artifact_id}: {ev} >= {version}")
                    return False
            return False  # already declared — do not duplicate

        dep = (
            f"\n    <dependency>\n"
            f"      <groupId>{group_id}</groupId>\n"
            f"      <artifactId>{artifact_id}</artifactId>\n"
            f"      <version>{version}</version>\n"
            f"      <!-- Security fix: {', '.join(cve_ids[:5])} -->\n"
            f"    </dependency>"
        )
        mgmt = re.search(r'<dependencyManagement>\s*<dependencies>', content, re.DOTALL)
        if mgmt:
            content = content[:mgmt.end()] + dep + content[mgmt.end():]
        else:
            block = (
                f"\n  <dependencyManagement>\n    <dependencies>"
                f"{dep}\n    </dependencies>\n  </dependencyManagement>"
            )
            close = re.search(r'</project>', content)
            if not close:
                print(f"  Cannot add depMgmt: no </project> in {pom_path}")
                return False
            content = content[:close.start()] + block + "\n" + content[close.start():]

        with open(pom_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Added {group_id}:{artifact_id}:{version} to depMgmt in {pom_path}")
        return True
    except OSError as exc:
        print(f"Error adding to depMgmt in {pom_path}: {exc}")
        return False
