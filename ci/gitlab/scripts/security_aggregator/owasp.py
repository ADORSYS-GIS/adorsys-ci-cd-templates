import re
from typing import Optional
from .models import CVEFinding
from .utils import load_json_file


KNOWN_JAR_MAPPINGS = {
    'spring-core': ('org.springframework', 'spring-core'),
    'spring-context': ('org.springframework', 'spring-context'),
    'spring-beans': ('org.springframework', 'spring-beans'),
    'spring-aop': ('org.springframework', 'spring-aop'),
    'spring-expression': ('org.springframework', 'spring-expression'),
    'spring-web': ('org.springframework', 'spring-web'),
    'spring-webmvc': ('org.springframework', 'spring-webmvc'),
    'spring-boot': ('org.springframework.boot', 'spring-boot'),
    'spring-security-core': ('org.springframework.security', 'spring-security-core'),
    'spring-security-web': ('org.springframework.security', 'spring-security-web'),
    'spring-security-config': ('org.springframework.security', 'spring-security-config'),
    'quarkus-arc': ('io.quarkus', 'quarkus-arc'),
    'quarkus-core': ('io.quarkus', 'quarkus-core'),
    'quarkus-vertx-utils': ('io.quarkus', 'quarkus-vertx-utils'),
    'resteasy-reactive': ('io.quarkus', 'resteasy-reactive'),
    'quarkus-bootstrap': ('io.quarkus', 'quarkus-bootstrap'),
    'quarkus-development-mode-spi': ('io.quarkus', 'quarkus-development-mode-spi'),
    'jackson-databind': ('com.fasterxml.jackson.core', 'jackson-databind'),
    'jackson-core': ('com.fasterxml.jackson.core', 'jackson-core'),
    'jackson-annotations': ('com.fasterxml.jackson.core', 'jackson-annotations'),
    'logback-classic': ('ch.qos.logback', 'logback-classic'),
    'logback-core': ('ch.qos.logback', 'logback-core'),
    'slf4j-api': ('org.slf4j', 'slf4j-api'),
    'guava': ('com.google.guava', 'guava'),
    'commons-lang3': ('org.apache.commons', 'commons-lang3'),
    'commons-io': ('commons-io', 'commons-io'),
    'httpclient': ('org.apache.httpcomponents', 'httpclient'),
    'httpcore': ('org.apache.httpcomponents', 'httpcore'),
    'netty-handler': ('io.netty', 'netty-handler'),
    'netty-codec-http': ('io.netty', 'netty-codec-http'),
    'netty-codec-http2': ('io.netty', 'netty-codec-http2'),
    'bouncy-castle': ('org.bouncycastle', 'bcprov-jdk18on'),
    'bcprov-jdk18on': ('org.bouncycastle', 'bcprov-jdk18on'),
    'snakeyaml': ('org.yaml', 'snakeyaml'),
    'tomcat-embed-core': ('org.apache.tomcat.embed', 'tomcat-embed-core'),
}


def extract_maven_coords_from_jar(jar_name: str) -> tuple[Optional[str], Optional[str]]:
    """Attempt to extract group:artifact from a JAR filename."""
    name_without_ext = jar_name
    if name_without_ext.endswith('.jar'):
        name_without_ext = name_without_ext[:-4]
    version_match = re.match(r'^(.+?)-(\d+\.\d+[.\d]*)$', name_without_ext)
    if version_match:
        artifact = version_match.group(1)
        if artifact in KNOWN_JAR_MAPPINGS:
            return KNOWN_JAR_MAPPINGS[artifact]
        return None, artifact
    if name_without_ext in KNOWN_JAR_MAPPINGS:
        return KNOWN_JAR_MAPPINGS[name_without_ext]
    return None, name_without_ext


def parse_owasp_report(report_path: str) -> list[CVEFinding]:
    """Parse OWASP Dependency-Check JSON report."""
    findings = []
    data = load_json_file(report_path)
    if not data:
        return findings
    dependencies = data.get('dependencies', [])
    for dep in dependencies:
        dep_name = dep.get('fileName', 'unknown')
        dep_path = dep.get('filePath', '')
        group_id = ''
        artifact_id = ''
        version = dep.get('version', '')
        evidence_list = dep.get('evidenceCollected', {})
        if isinstance(evidence_list, dict):
            for evidence in evidence_list.get('vendorEvidence', []):
                if evidence.get('name') in ('group id', 'groupId') and not group_id and evidence.get('value'):
                    group_id = evidence['value']
            for evidence in evidence_list.get('productEvidence', []):
                if evidence.get('name') in ('artifact id', 'artifactId') and not artifact_id and evidence.get('value'):
                    artifact_id = evidence['value']
                if evidence.get('name') in ('version', 'product version') and not version and evidence.get('value'):
                    version = evidence['value']
        maven_coords = dep.get('mavenContent', {})
        if isinstance(maven_coords, dict):
            if not group_id:
                group_id = maven_coords.get('groupId', '')
            if not artifact_id:
                artifact_id = maven_coords.get('artifactId', '')
            if not version:
                version = maven_coords.get('version', '')
        if group_id and artifact_id:
            package_name = f"{group_id}:{artifact_id}"
        else:
            guessed_group, guessed_artifact = extract_maven_coords_from_jar(dep_name)
            if guessed_group and guessed_artifact:
                package_name = f"{guessed_group}:{guessed_artifact}"
                if not group_id:
                    group_id = guessed_group
                if not artifact_id:
                    artifact_id = guessed_artifact
            else:
                package_name = dep_name
        # Fallback: extract version from the JAR filename when all other sources are empty
        if not version and dep_name.endswith('.jar'):
            name_no_ext = dep_name[:-4]
            v_match = re.match(r'^.+?-(\d+\.\d+[\d.]*)(?:-\w+)?$', name_no_ext)
            if v_match:
                version = v_match.group(1)
        for vuln in dep.get('vulnerabilities', []):
            cve_id = vuln.get('name', '')
            if not cve_id.startswith('CVE-'):
                continue
            severity = vuln.get('severity', 'UNKNOWN').upper()
            if severity not in ['HIGH', 'CRITICAL']:
                continue
            description = vuln.get('description', '')
            fixed_version = None
            for ref in vuln.get('references', []):
                ref_name = ref.get('name', '')
                if 'fix' in ref_name.lower() or 'advisory' in ref_name.lower() or 'upgrade' in ref_name.lower():
                    match = re.search(r'(\d+\.\d+\.\d+)', ref_name)
                    if match:
                        fixed_version = match.group(1)
                        break
            if not fixed_version:
                cvss_data = vuln.get('cvssv3') or vuln.get('cvssv2') or {}
                if isinstance(cvss_data, dict):
                    for note in cvss_data.get('note', '').split(','):
                        note = note.strip()
                        version_match = re.search(r'(\d+\.\d+\.\d+)', note)
                        if version_match:
                            fixed_version = version_match.group(1)
                            break
            findings.append(CVEFinding(
                cve_id=cve_id, severity=severity, package_name=package_name,
                package_version=version, fixed_version=fixed_version,
                source='owasp', file_path=dep_path, description=description))
    return findings