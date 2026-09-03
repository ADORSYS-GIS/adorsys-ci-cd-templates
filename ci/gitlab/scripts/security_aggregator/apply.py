"""Fix application — writes resolved version bumps into project files.

Extracted from cli.py so each module stays under 200 lines.
Handles Maven (pom.xml), npm (package.json), and Docker (Dockerfile) updates.
"""
import os
import subprocess
import traceback
from typing import Optional

from .models import Remediation
from .maven_fixer import find_pom_files, apply_maven_version, update_property_in_pom_files
from .maven_fixer_props import find_version_property, add_to_dependency_management
from .fixers import (
    find_dockerfiles, find_package_json_files,
    apply_package_json_version, apply_dockerfile_version,
)
from .versions import is_downgrade


def _apply_maven(rem: Remediation, pom_files: list[str]) -> int:
    """Apply a Maven version fix. Returns the number of changed locations."""
    if ':' not in rem.package_name:
        print(f"  Skip maven fix for {rem.package_name}: no group:artifact")
        return 0
    group_id, artifact_id = rem.package_name.split(':', 1)
    if rem.current_version and is_downgrade(rem.current_version, rem.fixed_version):
        print(f"  SKIP {group_id}:{artifact_id}: downgrade "
              f"{rem.current_version} → {rem.fixed_version}")
        return 0

    applied = 0
    prop_name: Optional[str] = None

    for pom in pom_files:
        changed, found_prop = apply_maven_version(pom, group_id, artifact_id, rem.fixed_version)
        if changed:
            applied += 1
        if found_prop and not prop_name:
            prop_name = found_prop

    if prop_name:
        applied += update_property_in_pom_files(pom_files, prop_name, rem.fixed_version)

    if applied == 0:
        hprop, _ = find_version_property(pom_files, group_id, artifact_id)
        if hprop:
            applied += update_property_in_pom_files(pom_files, hprop, rem.fixed_version)

    if applied == 0 and pom_files:
        # Last resort: inject explicit <dependencyManagement> entry
        root_pom = os.path.join(os.path.dirname(pom_files[0]), 'pom.xml')
        if not os.path.exists(root_pom):
            root_pom = pom_files[0]
        if add_to_dependency_management(
            root_pom, group_id, artifact_id, rem.fixed_version,
            rem.cve_ids, current_version=rem.current_version,
        ):
            applied += 1

    return applied


def apply_fixes(remediations: list[Remediation], project_dir: str) -> int:
    """Apply all actionable remediations to project files. Returns fix count."""
    actionable = [r for r in remediations if r.status == 'actionable' and r.fixed_version]
    if not actionable:
        print("No actionable remediations to apply.")
        return 0

    pom_files = find_pom_files(project_dir)
    dockerfiles = find_dockerfiles(project_dir)
    package_json_files = find_package_json_files(project_dir)
    print(
        f"Found {len(pom_files)} pom.xml, {len(dockerfiles)} Dockerfiles, "
        f"{len(package_json_files)} package.json"
    )

    applied = 0
    npm_dirs: set[str] = set()
    try:
        for rem in actionable:
            if rem.package_type == 'maven':
                applied += _apply_maven(rem, pom_files)
            elif rem.package_type == 'npm':
                pkg = rem.package_name.split(':')[-1]
                for pj in package_json_files:
                    if apply_package_json_version(pj, pkg, rem.fixed_version):
                        applied += 1
                        npm_dirs.add(os.path.dirname(pj))
            elif rem.package_type == 'docker':
                for df in dockerfiles:
                    if apply_dockerfile_version(df, rem.package_name, rem.fixed_version):
                        applied += 1

        for npm_dir in sorted(npm_dirs):
            lock = os.path.join(npm_dir, 'package-lock.json')
            cmd = ['npm', 'install'] + (['--package-lock-only'] if os.path.exists(lock) else [])
            res = subprocess.run(
                cmd, cwd=npm_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            if res.returncode != 0:
                print(res.stdout)
                print(f"  WARNING: npm install failed in {npm_dir}")

    except Exception as exc:
        print(f"ERROR during fix application: {exc}")
        traceback.print_exc()

    return applied
