import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from .models import CVEFinding, Remediation


def generate_unified_report(findings: list[CVEFinding], remediations: list[Remediation], output_dir: str):
    """Generate unified report files."""
    os.makedirs(output_dir, exist_ok=True)
    actionable = [r for r in remediations if r.status == 'actionable']

    findings_data = {
        'generated_at': datetime.now().isoformat(),
        'total_findings': len(findings),
        'findings': [
            {
                'cve_id': f.cve_id,
                'severity': f.severity,
                'package': f.package_name,
                'installed_version': f.package_version,
                'fixed_version': f.fixed_version,
                'source': f.source,
                'file': f.file_path,
                'description': f.description,
                'is_transitive': f.is_transitive,
                'parent_dependency': f.parent_dependency,
                'dep_chain': f.dep_chain,
            }
            for f in findings
        ]
    }

    with open(os.path.join(output_dir, 'unified-findings.json'), 'w') as f:
        json.dump(findings_data, f, indent=2)

    remediation_data = {
        'generated_at': datetime.now().isoformat(),
        'total_remediations': len(actionable),
        'not_affected_count': len([r for r in remediations if r.status == 'not-affected']),
        'no_fix_count': len([r for r in remediations if r.status == 'no-fix']),
        'remediations': [
            {
                'package': r.package_name,
                'type': r.package_type,
                'current_version': r.current_version,
                'fixed_version': r.fixed_version,
                'cve_ids': r.cve_ids,
                'source_files': r.source_files,
                'strategy': r.strategy,
                'risk_level': r.risk_level,
                'status': r.status,
                'is_transitive': r.is_transitive,
                'parent_dependency': r.parent_dependency,
                'dep_chain': r.dep_chain,
                'fix_guidance': r.fix_guidance,
            }
            for r in remediations  # all statuses — shell script filters by .status
        ]
    }

    with open(os.path.join(output_dir, 'remediation-plan.json'), 'w') as f:
        json.dump(remediation_data, f, indent=2)

    summary = {
        'summary': {
            'total_cves': len(findings),
            'high_count': len([f for f in findings if f.severity == 'HIGH']),
            'critical_count': len([f for f in findings if f.severity == 'CRITICAL']),
            'actionable_count': len(actionable),
            'not_affected_count': len([r for r in remediations if r.status == 'not-affected']),
            'no_fix_count': len([r for r in remediations if r.status == 'no-fix']),
            'unique_packages': len(set(f.package_name for f in findings))
        },
        'by_source': {},
        'top_packages': []
    }

    for f in findings:
        summary['by_source'][f.source] = summary['by_source'].get(f.source, 0) + 1

    pkg_counts = defaultdict(int)
    for f in findings:
        pkg_counts[f.package_name] += 1

    for pkg, count in sorted(pkg_counts.items(), key=lambda x: -x[1])[:10]:
        summary['top_packages'].append({'package': pkg, 'cve_count': count})

    with open(os.path.join(output_dir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    maven_remediations = [r for r in actionable if r.package_type == 'maven']
    pom_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    pom_xml += '<!-- Maven dependency updates for security remediation -->\n'
    pom_xml += '<!-- Apply these updates to your pom.xml dependencyManagement section -->\n\n'
    if maven_remediations:
        pom_xml += '<dependencyManagement>\n  <dependencies>\n'
        for rem in maven_remediations:
            if ':' in rem.package_name:
                group_id, artifact_id = rem.package_name.split(':', 1)
            else:
                group_id = rem.package_name
                artifact_id = rem.package_name
            pom_xml += f'    <dependency>\n'
            pom_xml += f'      <groupId>{group_id}</groupId>\n'
            pom_xml += f'      <artifactId>{artifact_id}</artifactId>\n'
            pom_xml += f'      <version>{rem.fixed_version}</version>\n'
            pom_xml += f'      <!-- Fixes: {", ".join(rem.cve_ids)} -->\n'
            pom_xml += f'    </dependency>\n'
        pom_xml += '  </dependencies>\n</dependencyManagement>\n'
    else:
        pom_xml += '<!-- No actionable Maven remediations found -->\n'
    with open(os.path.join(output_dir, 'pom-updates.xml'), 'w') as f:
        f.write(pom_xml)
    print(f"  - pom-updates.xml ({len(maven_remediations)} updates)")

    docker_remediations = [r for r in actionable if r.package_type == 'docker' or r.package_name == 'Dockerfile']
    with open(os.path.join(output_dir, 'dockerfile-updates.txt'), 'w') as f:
        f.write("# Dockerfile image updates for security remediation\n")
        f.write("# Apply these updates to your Dockerfile FROM statements\n\n")
        if docker_remediations:
            for rem in docker_remediations:
                f.write(f"# Fixes: {', '.join(rem.cve_ids)}\n")
                f.write(f"{rem.package_name}: {rem.current_version} -> {rem.fixed_version}\n\n")
        else:
            f.write("# No actionable Dockerfile remediations found\n")
    print(f"  - dockerfile-updates.txt ({len(docker_remediations)} updates)")

    print(f"\nGenerated reports in {output_dir}:")
    print(f"  - unified-findings.json ({len(findings)} CVEs)")
    print(f"  - remediation-plan.json ({len(actionable)} actionable)")
    print(f"  - summary.json")
    # Always create .fixes-applied so the CI artifact path is never missing.
    # cli.py overwrites it with the actual count when fixes are applied.
    fixes_path = os.path.join(output_dir, '.fixes-applied')
    if not os.path.exists(fixes_path):
        with open(fixes_path, 'w') as f:
            f.write('0\n')