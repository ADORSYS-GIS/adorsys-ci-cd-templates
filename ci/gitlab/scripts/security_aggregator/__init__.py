from .models import CVEFinding, Remediation
from .aggregator import aggregate_findings, deduplicate_findings, resolve_fixes
from .maven_fixer import find_pom_files, apply_maven_version, update_property_in_pom_files
from .maven_fixer_props import find_version_property, add_to_dependency_management
from .fixers import (
    find_dockerfiles,
    find_package_json_files,
    apply_package_json_version,
    apply_dockerfile_version,
)
from .reporter import generate_unified_report
from .owasp import parse_owasp_report
from .trivy import parse_trivy_fs_report, parse_trivy_dockerfile_report
from .cyclonedx import (
    parse_cyclonedx_bom,
    build_cyclonedx_index,
    resolve_maven_coords,
    build_dependency_graph,
    build_reverse_dependency_graph,
    build_purl_to_bomref,
    find_parent_dependencies,
)
from .resolver import find_fix
from .nvd import query_fix_boundary
from .versions import compare_maven, is_downgrade, is_stable_version, strip_maven_qualifier