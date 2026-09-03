import os
import re
from typing import Optional
from .models import CVEFinding
from .utils import load_json_file


def parse_cyclonedx_bom(report_path: str) -> list[CVEFinding]:
    """Parse CycloneDX BOM for dependencies (not CVEs)."""
    findings = []
    data = load_json_file(report_path)
    if not data:
        return findings

    for component in data.get('components', []):
        pass

    return findings


def build_cyclonedx_index(bom_path: str) -> dict[str, dict]:
    """Build a lookup from JAR filename and (group, artifact) to BOM component data.

    Returns a dict mapping:
      - lowercase JAR filename -> component dict
      - 'group:artifact' -> component dict
    """
    index: dict[str, dict] = {}
    data = load_json_file(bom_path)
    if not data:
        print(f"Warning: Could not load CycloneDX BOM from {bom_path}")
        return index

    for component in data.get('components', []):
        group = component.get('group', '')
        name = component.get('name', '')
        version = component.get('version', '')
        purl = component.get('purl', '')

        maven_key = f"{group}:{name}" if group else name

        entry = {
            'group': group,
            'name': name,
            'version': version,
            'purl': purl,
        }

        if group and name:
            index[maven_key.lower()] = entry

        for ref in component.get('evidence', {}).get('occurrences', []):
            loc = ref.get('location', '')
            if loc:
                basename = os.path.basename(loc).lower()
                if basename not in index:
                    index[basename] = entry

        filename = component.get('properties', {})
        if isinstance(filename, list):
            for prop in filename:
                if prop.get('name') == 'fileName':
                    fn = prop.get('value', '').lower()
                    if fn:
                        index[fn] = entry

    return index


def build_dependency_graph(bom_path: str) -> dict[str, list[str]]:
    """Build a dependency graph from CycloneDX BOM.

    Returns a dict mapping component BOM-Ref -> list of BOM-Refs it depends on.
    This allows walking from a direct dependency to its transitive dependencies.
    """
    graph: dict[str, list[str]] = {}
    data = load_json_file(bom_path)
    if not data:
        return graph

    for dep_entry in data.get('dependencies', []):
        ref = dep_entry.get('ref', '')
        depends_on = dep_entry.get('dependsOn', [])
        if ref:
            graph[ref] = depends_on

    return graph


def build_reverse_dependency_graph(bom_path: str) -> dict[str, list[str]]:
    """Build a reverse dependency graph: transitive BOM-Ref -> list of parent BOM-Refs.

    For each component, tells you which components depend on it directly.
    """
    forward = build_dependency_graph(bom_path)
    reverse: dict[str, list[str]] = {}
    for parent, children in forward.items():
        for child in children:
            reverse.setdefault(child, []).append(parent)
    return reverse


def build_purl_to_bomref(bom_path: str) -> dict[str, str]:
    """Map purl -> bom-ref for dependency graph lookups."""
    data = load_json_file(bom_path)
    if not data:
        return {}
    purl_map: dict[str, str] = {}
    maven_key_map: dict[str, str] = {}
    for component in data.get('components', []):
        bom_ref = component.get('bom-ref', '')
        purl = component.get('purl', '')
        group = component.get('group', '')
        name = component.get('name', '')
        if purl and bom_ref:
            purl_map[purl] = bom_ref
        maven_key = f"{group}:{name}".lower() if group else name.lower()
        if maven_key and bom_ref:
            maven_key_map[maven_key] = bom_ref
    purl_map.update(maven_key_map)
    return purl_map


def find_parent_dependencies(
    bom_path: str, package_name: str, cdx_index: dict[str, dict],
) -> tuple[Optional[str], list[str]]:
    """Find the direct (parent) dependency that brings in a transitive package.

    Returns (parent_dependency, dep_chain) where:
      parent_dependency: the first direct dependency parent (group:artifact or name)
      dep_chain: full chain from root to the vulnerable package

    If the package is a direct dependency, returns (None, []).
    """
    reverse_graph = build_reverse_dependency_graph(bom_path)
    purl_map = build_purl_to_bomref(bom_path)
    forward_graph = build_dependency_graph(bom_path)

    pkg_key = package_name.lower()
    if pkg_key not in purl_map:
        jar_key = package_name.lower()
        if jar_key.endswith('.jar'):
            jar_key = jar_key[:-4]
        bom_ref = purl_map.get(pkg_key) or purl_map.get(jar_key) or None
    else:
        bom_ref = purl_map[pkg_key]

    if not bom_ref:
        return None, []

    parents = reverse_graph.get(bom_ref, [])
    if not parents:
        return None, []

    chain = [package_name]
    visited = {bom_ref}
    current_refs = [bom_ref]
    direct_parent = None

    while current_refs and not direct_parent:
        next_refs = []
        for ref in current_refs:
            parent_refs = reverse_graph.get(ref, [])
            if not parent_refs:
                entry = cdx_index.get(_bomref_to_key(ref, cdx_index), {})
                parent_name = f"{entry.get('group', '')}:{entry.get('name', '')}" if entry.get('group') else entry.get('name', ref)
                direct_parent = parent_name
                break
            for p in parent_refs:
                if p not in visited:
                    visited.add(p)
                    next_refs.append(p)
                    entry = cdx_index.get(_bomref_to_key(p, cdx_index), {})
                    chain_name = f"{entry.get('group', '')}:{entry.get('name', '')}" if entry.get('group') else entry.get('name', p)
                    chain.append(chain_name)
        current_refs = next_refs

    if direct_parent:
        chain.reverse()
        return direct_parent, chain

    return None, chain


def _bomref_to_key(bom_ref: str, cdx_index: dict[str, dict]) -> str:
    """Attempt to convert a bom-ref to a lookup key for cdx_index.

    bom-ref values are often full purls like pkg:maven/group/artifact@version.
    cdx_index keys are 'group:artifact' (lowercase).  Try to extract that form.
    """
    ref = bom_ref.lower()
    # Fast path: already a key in the index
    if ref in cdx_index:
        return ref
    # purl form: pkg:maven/group/artifact@version  →  group:artifact
    m = re.match(r'^pkg:maven/([^/]+)/([^@]+)@', ref)
    if m:
        candidate = f"{m.group(1)}:{m.group(2)}"
        if candidate in cdx_index:
            return candidate
    # Fallback: return as-is (caller handles missing entry gracefully)
    return ref


def resolve_maven_coords(finding: CVEFinding, cyclonedx_index: dict[str, dict]) -> tuple[str, str]:
    """Resolve Maven group:artifact for a finding using CycloneDX index.

    Returns (group_id, artifact_id) tuple.
    """
    pkg = finding.package_name

    if ':' in pkg and len(pkg.split(':')) == 2:
        parts = pkg.split(':')
        return parts[0], parts[1]

    jar_name = pkg.lower()
    if jar_name.endswith('.jar'):
        jar_name = jar_name[:-4]

    if jar_name in cyclonedx_index:
        entry = cyclonedx_index[jar_name]
        return entry.get('group', ''), entry.get('name', '')

    version_match = re.match(r'^(.+?)-\d+\.\d+', jar_name)
    if version_match:
        artifact = version_match.group(1)
        if artifact in cyclonedx_index:
            entry = cyclonedx_index[artifact]
            return entry.get('group', ''), entry.get('name', '')

    from .owasp import extract_maven_coords_from_jar
    guessed_group, guessed_artifact = extract_maven_coords_from_jar(pkg)
    if guessed_group and guessed_artifact:
        return guessed_group, guessed_artifact

    return '', pkg