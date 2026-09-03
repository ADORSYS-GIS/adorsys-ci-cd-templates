from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEFinding:
    cve_id: str
    severity: str
    package_name: str
    package_version: str
    fixed_version: Optional[str]
    source: str
    file_path: Optional[str] = None
    description: Optional[str] = None
    is_transitive: Optional[bool] = None
    parent_dependency: Optional[str] = None
    dep_chain: list = field(default_factory=list)


@dataclass
class Remediation:
    package_name: str
    package_type: str
    current_version: str
    fixed_version: str
    cve_ids: list = field(default_factory=list)
    source_files: list = field(default_factory=list)
    strategy: str = ''
    risk_level: str = ''
    status: str = 'actionable'
    is_transitive: Optional[bool] = None
    parent_dependency: Optional[str] = None
    dep_chain: list = field(default_factory=list)
    fix_guidance: Optional[str] = None