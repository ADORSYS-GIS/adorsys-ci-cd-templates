"""Aggregate security findings from all scanner tools and resolve fix versions.

Sources: OWASP Dependency-Check, Trivy (FS + Dockerfile), CycloneDX BOM.
Fix resolution: NVD version-range analysis + Maven Central version search.
OSV is not consulted — it is unreliable for Maven ecosystem fix-version data.
"""
import os
import re
from collections import defaultdict
from .models import CVEFinding, Remediation
from .owasp import parse_owasp_report
from .trivy import parse_trivy_fs_report, parse_trivy_dockerfile_report
from .cyclonedx import build_cyclonedx_index, find_parent_dependencies, resolve_maven_coords
from .resolver import find_fix, STATUS_NOT_AFFECTED, STATUS_NO_FIX
from .versions import is_downgrade
from .fix_plan import resolve_fixes  # noqa: F401 — re-exported for backward compatibility


def aggregate_findings(
    project_dir: str,
    severity_filter: list[str],
) -> tuple[list[CVEFinding], dict, dict[str, dict]]:
    """Parse all scanner reports and return filtered findings."""
    all_findings: list[CVEFinding] = []
    sources: dict = defaultdict(int)
    report_paths = {
        'owasp':            os.path.join(project_dir, 'target', 'dependency-check-report.json'),
        'trivy-fs':         os.path.join(project_dir, 'trivy-fs-report.json'),
        'trivy-dockerfile': os.path.join(project_dir, 'trivy-dockerfile-report.json'),
        'cyclonedx-bom':    os.path.join(project_dir, 'target', 'bom.json'),
    }
    parsers = {
        'owasp':            parse_owasp_report,
        'trivy-fs':         parse_trivy_fs_report,
        'trivy-dockerfile': parse_trivy_dockerfile_report,
    }
    for key, parser in parsers.items():
        path = report_paths[key]
        if os.path.exists(path):
            found = parser(path)
            all_findings.extend(found)
            sources[key] = len(found)
            print(f"Parsed {key}: {len(found)} findings")

    cdx_index: dict[str, dict] = {}
    if os.path.exists(report_paths['cyclonedx-bom']):
        cdx_index = build_cyclonedx_index(report_paths['cyclonedx-bom'])
        print(f"CycloneDX BOM index: {len(cdx_index)} entries")

        parent_map = _build_parent_map_from_owasp(
            report_paths['owasp'], cdx_index,
        )
        for finding in all_findings:
            if finding.is_transitive is None and finding.source == 'owasp':
                _enrich_transitive_owasp(finding, report_paths['owasp'], cdx_index)

        bom_path = report_paths['cyclonedx-bom']
        for finding in all_findings:
            if not finding.parent_dependency and os.path.exists(bom_path):
                parent, chain = find_parent_dependencies(
                    bom_path, finding.package_name, cdx_index,
                )
                if parent:
                    finding.parent_dependency = parent
                    finding.dep_chain = chain
                    finding.is_transitive = True
                elif finding.is_transitive is None:
                    finding.is_transitive = False

        if parent_map:
            for finding in all_findings:
                if finding.source == 'owasp' and not finding.parent_dependency:
                    pkg = finding.package_name.lower()
                    # Try several key variants: full name, artifact-only (group:artifact → artifact),
                    # jar-without-extension, jar-without-version.
                    artifact_only = pkg.split(':')[-1] if ':' in pkg else pkg
                    jar_no_ext = artifact_only[:-4] if artifact_only.endswith('.jar') else artifact_only
                    v_m = re.match(r'^(.+?)-\d+\.\d+', jar_no_ext)
                    no_version = v_m.group(1) if v_m else jar_no_ext
                    parent_val = (
                        parent_map.get(pkg)
                        or parent_map.get(artifact_only)
                        or parent_map.get(jar_no_ext)
                        or parent_map.get(no_version)
                    )
                    if parent_val:
                        finding.parent_dependency = parent_val
                        finding.is_transitive = True

    return [f for f in all_findings if f.severity in severity_filter], dict(sources), cdx_index


def _build_parent_map_from_owasp(
    owasp_path: str, cdx_index: dict[str, dict],
) -> dict[str, str]:
    """Build a map: child_jar -> parent_jar from OWASP nested dependencies.

    OWASP reports include 'relatedDependencies' which list what a dependency
    is bundled inside of. We use this to infer parent-child relationships.
    """
    if not os.path.exists(owasp_path):
        return {}
    from .utils import load_json_file
    data = load_json_file(owasp_path)
    if not data:
        return {}

    parent_map: dict[str, str] = {}
    for dep in data.get('dependencies', []):
        dep_name = dep.get('fileName', '')
        children = dep.get('relatedDependencies', [])
        if children and dep_name:
            jar_key = dep_name.lower()
            if jar_key.endswith('.jar'):
                jar_key = jar_key[:-4]
            for child in children:
                child_name = child.get('fileName', '')
                child_key = child_name.lower()
                if child_key.endswith('.jar'):
                    child_key = child_key[:-4]
                if child_key and child_key != jar_key and child_key not in parent_map:
                    parent_map[child_key] = jar_key
            for child in children:
                child_name = child.get('fileName', '')
                child_key = child_name.lower()
                if child_key.endswith('.jar'):
                    child_key = child_key[:-4]
                if child_key and child_key != jar_key:
                    v_match = re.match(r'^(.+?)-(\d+\.\d+[.\d]*)$', child_key)
                    clean = v_match.group(1) if v_match else child_key
                    if clean not in parent_map and child_key not in parent_map:
                        parent_map[clean] = jar_key
    return parent_map


def _enrich_transitive_owasp(
    finding: CVEFinding, owasp_path: str, cdx_index: dict[str, dict],
) -> None:
    """Check if an OWASP finding is for a transitive dependency.

    Uses the 'isVirtual' flag and 'relatedDependency' structure in OWASP
    reports. A dependency listed as a child of another is transitive.
    """
    from .utils import load_json_file
    if not os.path.exists(owasp_path):
        return
    data = load_json_file(owasp_path)
    if not data:
        return

    finding_key = finding.package_name.lower()
    jar_match = finding_key
    if jar_match.endswith('.jar'):
        jar_match = jar_match[:-4]

    for dep in data.get('dependencies', []):
        is_virtual = dep.get('isVirtual', False)
        if is_virtual:
            continue
        dep_name = dep.get('fileName', '')
        dep_key = dep_name.lower()
        if dep_key.endswith('.jar'):
            dep_key = dep_key[:-4]

        v_match = dep_key
        m = re.search(r'-\d+\.\d+', dep_key)
        if m:
            v_match = dep_key[:m.start()]

        matched = (
            finding_key == dep_key
            or finding_key == v_match
            or jar_match == dep_key
            or jar_match == v_match
        )
        if not matched:
            continue

        related = dep.get('relatedDependencies', [])
        if related:
            finding.is_transitive = False
        else:
            pass
        break


def deduplicate_findings(findings: list[CVEFinding]) -> list[CVEFinding]:
    """Deduplicate by (CVE, package, version), merging fixed_version when available."""
    seen: dict = {}
    for f in findings:
        key = (f.cve_id, f.package_name, f.package_version)
        if key not in seen:
            seen[key] = f
        elif f.fixed_version and not seen[key].fixed_version:
            seen[key].fixed_version = f.fixed_version
    return list(seen.values())