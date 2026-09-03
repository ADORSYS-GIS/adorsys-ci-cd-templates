"""Maven POM file version updaters.

Applies version changes to pom.xml files via:
  - Explicit <version> declarations
  - ${property} references
  - <dependencyManagement> blocks

Property/BOM helpers live in maven_fixer_props.py.
"""
import os
import re
from typing import Optional

from .versions import is_downgrade


def find_pom_files(project_dir: str) -> list[str]:
    """Walk project_dir and return all pom.xml paths (skips .* and target/)."""
    result = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'target']
        if 'pom.xml' in files:
            result.append(os.path.join(root, 'pom.xml'))
    return result


def _dep_pat(group_id: str, artifact_id: str) -> re.Pattern:
    return re.compile(
        rf'<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*'
        rf'<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*'
        rf'<version>([^<]+)</version>',
        re.DOTALL,
    )


def _dep_mgmt_pat(group_id: str, artifact_id: str) -> re.Pattern:
    return re.compile(
        rf'<dependencyManagement>.*?'
        rf'<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*'
        rf'<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*'
        rf'<version>([^<]+)</version>',
        re.DOTALL,
    )


def _try_direct(
    content: str, group_id: str, artifact_id: str, new_version: str,
) -> tuple[str, bool, Optional[str]]:
    """Try updating an explicit <version> tag; returns (content, changed, prop_name)."""
    for pat in (_dep_pat(group_id, artifact_id), _dep_mgmt_pat(group_id, artifact_id)):
        m = pat.search(content)
        if not m:
            continue
        old_ver = m.group(1).strip()
        if old_ver.startswith('${'):
            prop_m = re.search(r'\$\{([^}]+)\}', old_ver)
            return content, False, prop_m.group(1).strip() if prop_m else None
        if is_downgrade(old_ver, new_version):
            print(f"  SKIP {group_id}:{artifact_id}: downgrade {old_ver} → {new_version}")
            return content, False, None
        content = content[:m.start(1)] + new_version + content[m.end(1):]
        return content, True, None
    return content, False, None


def _try_property(
    content: str, group_id: str, artifact_id: str, new_version: str,
) -> tuple[str, bool, Optional[str]]:
    """Try updating via a ${property} version reference; returns (content, changed, prop_name)."""
    prop_ref = re.compile(
        rf'<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*'
        rf'<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*'
        rf'<version>\s*\${{([^}}]+)}}\s*</version>',
        re.DOTALL,
    )
    m = prop_ref.search(content)
    if not m:
        return content, False, None
    prop_name = m.group(1).strip()
    pp = re.compile(rf'(<{re.escape(prop_name)}>)([^<]+)(</{re.escape(prop_name)}>)')
    pm = pp.search(content)
    if pm:
        if is_downgrade(pm.group(2), new_version):
            print(f"  SKIP property {prop_name}: downgrade {pm.group(2)} → {new_version}")
            return content, False, prop_name
        content = content[:pm.start(2)] + new_version + content[pm.end(2):]
        return content, True, prop_name
    return content, False, prop_name


def apply_maven_version(
    pom_path: str, group_id: str, artifact_id: str, new_version: str,
) -> tuple[bool, Optional[str]]:
    """Update group_id:artifact_id to new_version in pom_path.

    Handles direct <version>, ${property} references, and <dependencyManagement>.
    Returns (changed, property_name).
    """
    try:
        with open(pom_path, encoding='utf-8') as f:
            content = f.read()
    except OSError as exc:
        print(f"Error reading {pom_path}: {exc}")
        return False, None

    original = content
    content, updated, prop_name = _try_direct(content, group_id, artifact_id, new_version)
    if not updated and prop_name is None:
        content, updated, prop_name = _try_property(content, group_id, artifact_id, new_version)

    if content != original:
        with open(pom_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {group_id}:{artifact_id} → {new_version} in {pom_path}")
        return True, prop_name
    return updated, prop_name


def update_property_in_pom_files(pom_files: list[str], prop_name: str, new_version: str) -> int:
    """Update a Maven property across all pom.xml files. Returns modified count."""
    count = 0
    pat = re.compile(rf'(<{re.escape(prop_name)}>)([^<]+)(</{re.escape(prop_name)}>)')
    for pom_path in pom_files:
        try:
            with open(pom_path, encoding='utf-8') as f:
                content = f.read()
            m = pat.search(content)
            if not m or m.group(2) == new_version:
                continue
            if is_downgrade(m.group(2), new_version):
                print(f"  SKIP {prop_name}: downgrade {m.group(2)} → {new_version} in {pom_path}")
                continue
            with open(pom_path, 'w', encoding='utf-8') as f:
                f.write(content[:m.start(2)] + new_version + content[m.end(2):])
            count += 1
            print(f"Updated property {prop_name} → {new_version} in {pom_path}")
        except OSError as exc:
            print(f"Error updating {pom_path}: {exc}")
    return count
