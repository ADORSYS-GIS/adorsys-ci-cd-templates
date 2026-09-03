import hashlib
import re
from typing import Optional
from .models import CVEFinding
from .utils import load_json_file
from .owasp import extract_maven_coords_from_jar


def _stable_id(text: str) -> str:
    """Deterministic 4-digit ID, unlike Python's per-process randomized hash()."""
    digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return f"{int(digest[:8], 16) % 10000:04d}"


def parse_trivy_fs_report(report_path: str) -> list[CVEFinding]:
    """Parse Trivy filesystem JSON report."""
    findings = []
    data = load_json_file(report_path)
    if not data:
        return findings

    for result in data.get('Results', []) or []:
        for vuln in result.get('Vulnerabilities', []) or []:
            cve_id = vuln.get('VulnerabilityID', '')
            if not cve_id:
                continue

            severity = vuln.get('Severity', 'UNKNOWN').upper()
            if severity not in ['HIGH', 'CRITICAL']:
                continue

            pkg_name = vuln.get('PkgName', vuln.get('PkgID', 'unknown'))
            package_version = vuln.get('InstalledVersion', '')
            fixed_version = vuln.get('FixedVersion')
            file_path = result.get('Target', '')
            description = vuln.get('Description', '')

            if vuln.get('PkgID') and ':' in vuln.get('PkgID', ''):
                parts = vuln['PkgID'].split(':')
                if len(parts) >= 3:
                    package_name = f"{parts[0]}:{parts[1]}"
                else:
                    package_name = pkg_name
            elif 'pom.xml' in file_path or '.jar' in pkg_name:
                guessed_group, guessed_artifact = extract_maven_coords_from_jar(pkg_name)
                if guessed_group:
                    package_name = f"{guessed_group}:{guessed_artifact}"
                else:
                    package_name = pkg_name
            else:
                package_name = pkg_name

            findings.append(CVEFinding(
                cve_id=cve_id,
                severity=severity,
                package_name=package_name,
                package_version=package_version,
                fixed_version=fixed_version,
                source='trivy-fs',
                file_path=file_path,
                description=description
            ))

    return findings


def parse_trivy_dockerfile_report(report_path: str) -> list[CVEFinding]:
    """Parse Trivy Dockerfile config JSON report.

    Handles both Misconfigurations and Vulnerabilities (from trivy fs scanning
    Dockerfiles). Misconfigurations get a DOCKERFILE- prefixed ID with no
    fixed_version. Vulnerabilities get real CVE IDs and fixed versions.
    """
    findings = []
    data = load_json_file(report_path)
    if not data:
        return findings

    for result in data.get('Results', []) or []:
        target = result.get('Target', '')

        for vuln in result.get('Vulnerabilities', []) or []:
            cve_id = vuln.get('VulnerabilityID', '')
            if not cve_id:
                continue
            severity = vuln.get('Severity', 'UNKNOWN').upper()
            if severity not in ['HIGH', 'CRITICAL']:
                continue
            pkg_name = vuln.get('PkgName', vuln.get('PkgID', ''))
            package_version = vuln.get('InstalledVersion', '')
            fixed_version = vuln.get('FixedVersion')
            description = vuln.get('Description', '')
            image_name = ''
            if 'dockerfile' in target.lower():
                image_name = pkg_name
            findings.append(CVEFinding(
                cve_id=cve_id,
                severity=severity,
                package_name=image_name or pkg_name or 'Dockerfile',
                package_version=package_version,
                fixed_version=fixed_version,
                source='trivy-dockerfile',
                file_path=target,
                description=description
            ))

        for misconfig in result.get('Misconfigurations', []) or []:
            severity = misconfig.get('Severity', 'UNKNOWN').upper()
            if severity not in ['HIGH', 'CRITICAL']:
                continue

            cve_id = misconfig.get('ID', '')
            title = misconfig.get('Title', '')
            description = misconfig.get('Description', '')
            file_path = result.get('Target', '')

            findings.append(CVEFinding(
                cve_id=cve_id or f"DOCKERFILE-{_stable_id(title)}",
                severity=severity,
                package_name='Dockerfile',
                package_version='',
                fixed_version=None,
                source='trivy-dockerfile',
                file_path=file_path,
                description=f"{title}: {description}"
            ))

    return findings