"""Fix version resolution and remediation plan building.

Resolves fix versions for CVE findings using NVD + Maven Central and
constructs the list of Remediation objects consumed by the reporter.
"""
from collections import defaultdict

from .models import CVEFinding, Remediation
from .cyclonedx import resolve_maven_coords
from .resolver import find_fix, STATUS_NOT_AFFECTED, STATUS_NO_FIX
from .versions import is_downgrade


def _pkg_type(finding: CVEFinding, cdx_index: dict) -> str:
    """Infer package ecosystem from finding metadata and CycloneDX index."""
    if finding.source == 'trivy-dockerfile':
        return 'docker'
    for key in (finding.package_name.lower(), finding.package_name.lower().split(':')[-1]):
        purl = cdx_index.get(key, {}).get('purl', '')
        if purl.startswith('pkg:npm/'):
            return 'npm'
        if purl.startswith('pkg:maven/'):
            return 'maven'
    if finding.source == 'trivy-fs':
        fp = (finding.file_path or '').lower()
        if 'package.json' in fp or 'node_modules' in fp:
            return 'npm'
    return 'maven'


def resolve_fixes(
    findings: list[CVEFinding],
    offline: bool = False,
    cdx_index: dict | None = None,
) -> list[Remediation]:
    """Resolve fix versions using NVD + Maven Central.

    Returns ALL remediations including non-actionable ones.
    Check rem.status: 'actionable' | 'not-affected' | 'no-fix'.
    Nothing is silently discarded.
    """
    if cdx_index is None:
        cdx_index = {}
    buckets: dict = defaultdict(lambda: Remediation('', '', '', ''))

    for finding in findings:
        key = (finding.package_name, finding.package_version or '')
        rem = buckets[key]
        rem.package_name = rem.package_name or finding.package_name
        rem.current_version = rem.current_version or finding.package_version or ''
        rem.package_type = rem.package_type or _pkg_type(finding, cdx_index)
        if finding.cve_id not in rem.cve_ids:
            rem.cve_ids.append(finding.cve_id)
        if finding.file_path and finding.file_path not in rem.source_files:
            rem.source_files.append(finding.file_path)

        # Propagate transitive dependency info from findings
        if finding.is_transitive and rem.is_transitive is None:
            rem.is_transitive = True
            rem.parent_dependency = finding.parent_dependency
            rem.dep_chain = finding.dep_chain

        if rem.fixed_version:
            continue
        if finding.fixed_version:
            # Scanner-reported fix: validate it is not a downgrade.
            # OWASP/Trivy may report a fix from an old NVD CPE range (e.g.
            # "4.3.16" for a Spring 4.x CVE) even when the installed version
            # is 6.2.18. Using that directly would be a regression.
            current = rem.current_version or ''
            scanner_fix = finding.fixed_version
            if current and is_downgrade(current, scanner_fix):
                print(f"  WARN: scanner fix {scanner_fix} < installed "
                      f"{current} for {rem.package_name} — re-resolving via NVD+Maven")
                # Fall through to find_fix below
            else:
                rem.fixed_version = scanner_fix
                rem.status = 'actionable'
                rem.strategy = 'scanner-reported'
                continue
        if offline or rem.package_type != 'maven':
            rem.status = STATUS_NO_FIX
            continue

        group_id, artifact_id = resolve_maven_coords(finding, cdx_index)
        if not group_id or not artifact_id:
            rem.status = STATUS_NO_FIX
            continue

        # Populate current_version when the scanner didn't include it.
        # (OWASP often omits version for jar-named findings.)
        if not rem.current_version:
            cdx_key = f"{group_id}:{artifact_id}".lower()
            cdx_ver = cdx_index.get(cdx_key, {}).get('version', '')
            if cdx_ver:
                rem.current_version = cdx_ver
                print(f"  CycloneDX version for {group_id}:{artifact_id}: {cdx_ver}")
            else:
                # Fallback: extract version from jar filename
                # e.g. "arc-3.29.4.jar" → "3.29.4",
                #      "netty-codec-protobuf-4.2.13.Final.jar" → "4.2.13.Final"
                import re
                m = re.search(
                    r'-((\d+\.\d+[\d.]*)(\-[A-Za-z]\w*)?)(?:\.jar)?$',
                    finding.package_name, re.IGNORECASE,
                )
                if m:
                    rem.current_version = m.group(1)
                    print(f"  Filename version for {group_id}:{artifact_id}: {rem.current_version}")

        fix, strategy, risk = find_fix(
            finding.cve_id, group_id, artifact_id, rem.current_version,
        )
        if fix:
            # A better fix was found — always take it, even if a previous CVE
            # for this package already set a fix (take the more conservative
            # i.e. higher version so all CVEs in the bucket are covered).
            from .versions import compare_maven
            if not rem.fixed_version or compare_maven(
                fix, rem.fixed_version
            ) > 0:
                rem.fixed_version = fix
                rem.strategy = strategy
                rem.risk_level = risk
            rem.status = 'actionable'
            rem.package_name = f"{group_id}:{artifact_id}"
        elif not rem.fixed_version:
            # Don't overwrite 'actionable' from a prior CVE that already found
            # a fix, but DO correct the dataclass default when no fix exists.
            rem.status = strategy  # STATUS_NOT_AFFECTED or STATUS_NO_FIX

    # Deduplicate remediations that resolved to the same package_name
    # (e.g. "arc-3.29.4.jar" and "io.quarkus:quarkus-arc" are the same).
    seen: dict[str, Remediation] = {}
    for rem in buckets.values():
        name = rem.package_name
        existing = seen.get(name)
        if existing is None:
            seen[name] = rem
        elif rem.status == 'actionable' and existing.status != 'actionable':
            rem.cve_ids = list(dict.fromkeys(existing.cve_ids + rem.cve_ids))
            seen[name] = rem
        elif rem.status == existing.status == 'actionable':
            from .versions import compare_maven
            if compare_maven(rem.fixed_version or '', existing.fixed_version or '') > 0:
                rem.cve_ids = list(dict.fromkeys(existing.cve_ids + rem.cve_ids))
                seen[name] = rem
            else:
                existing.cve_ids = list(dict.fromkeys(existing.cve_ids + rem.cve_ids))
        else:
            existing.cve_ids = list(dict.fromkeys(existing.cve_ids + rem.cve_ids))

    # Generate fix_guidance for transitive dependencies
    for rem in seen.values():
        if rem.is_transitive and rem.parent_dependency:
            if rem.status == 'actionable' and rem.fixed_version:
                rem.fix_guidance = (
                    f"Transitive dependency — update {rem.parent_dependency} "
                    f"to pull in {rem.package_name} {rem.fixed_version}, "
                    f"or add <dependencyManagement> to pin the version."
                )
            elif rem.status == 'no-fix':
                rem.fix_guidance = (
                    f"Transitive dependency — no newer release of {rem.package_name} "
                    f"available. Check if {rem.parent_dependency} has an update "
                    f"that pulls a patched version, or add <dependencyManagement> override."
                )
            elif rem.status == 'not-affected':
                rem.fix_guidance = (
                    f"Transitive dependency — NVD indicates current version is outside "
                    f"the vulnerable range. Verify with {rem.parent_dependency} maintainers."
                )
            elif rem.package_type == 'maven':
                rem.fix_guidance = (
                    f"Transitive dependency of {rem.parent_dependency}. "
                    f"Override via <dependencyManagement> in pom.xml."
                )
        elif rem.is_transitive and not rem.parent_dependency:
            if rem.package_type == 'maven':
                rem.fix_guidance = (
                    f"Transitive dependency — not declared directly in pom.xml. "
                    f"Use <dependencyManagement> to pin version, or check parent BOM."
                )

    return list(seen.values())
