#!/usr/bin/env python3
"""Decorate and validate CycloneDX 1.6 Maven reactor BOMs."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema


def fail(message):
    raise SystemExit(f"SBOM validation failed: {message}")


def text(element, name):
    child = element.find(f"{{*}}{name}")
    return child.text.strip() if child is not None and child.text else ""


def project_artifact_ids(pom_path):
    root = ET.parse(pom_path).getroot()
    artifact_id = text(root, "artifactId")
    artifact_ids = {artifact_id} if artifact_id else set()
    modules = root.find("{*}modules")
    if modules is None:
        return artifact_ids

    for module in modules.findall("{*}module"):
        module_path = Path(module.text.strip())
        module_pom = pom_path.parent / module_path
        module_pom = module_pom if module_pom.name == "pom.xml" else module_pom / "pom.xml"
        if not module_pom.is_file():
            fail(f"reactor module POM is missing: {module_pom}")
        artifact_ids.update(project_artifact_ids(module_pom))
    return artifact_ids


def main():
    if len(sys.argv) != 6:
        fail("usage: validate-maven-sbom.py BOM SCHEMA POM BRANCH COMMIT")

    bom_path, schema_path, pom_path = map(Path, sys.argv[1:4])
    branch, commit = sys.argv[4:6]
    if not bom_path.is_file() or bom_path.stat().st_size == 0:
        fail(f"BOM is missing or empty: {bom_path}")
    try:
        bom = json.loads(bom_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(str(error))

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(
        validator.iter_errors(bom),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors[:5]
        )
        fail(f"not valid against CycloneDX 1.6 schema: {details}")

    metadata = bom.get("metadata") or {}
    root_component = metadata.get("component") or {}
    artifact_ids = project_artifact_ids(pom_path)
    root_artifact_id = text(ET.parse(pom_path).getroot(), "artifactId")
    if not root_artifact_id or root_component.get("name") != root_artifact_id:
        fail(
            "metadata.component does not describe the root Maven project "
            f"(expected artifactId {root_artifact_id!r})"
        )

    components = bom.get("components") or []
    if not components:
        fail("no dependency components were generated")
    component_refs = {component.get("bom-ref") for component in components}
    if any(not component.get("bom-ref") for component in components):
        fail("a component is missing its bom-ref")
    if not any(component.get("purl") for component in components):
        fail("no component has a package URL identifier")

    component_names = {component.get("name") for component in components}
    missing_modules = artifact_ids - {root_artifact_id} - component_names
    if missing_modules:
        fail(f"reactor modules are missing from the aggregate BOM: {sorted(missing_modules)}")

    root_ref = root_component.get("bom-ref")
    dependencies = bom.get("dependencies") or []
    if not root_ref or not dependencies:
        fail("the SBOM is missing root or dependency relationship data")
    dependency_refs = {dependency.get("ref") for dependency in dependencies}
    if root_ref not in dependency_refs:
        fail("the root project has no dependency relationship entry")
    known_refs = component_refs | {root_ref}
    edge_count = 0
    for dependency in dependencies:
        if dependency.get("ref") not in known_refs:
            fail(f"dependency relationship references an unknown component: {dependency.get('ref')}")
        for dependency_ref in dependency.get("dependsOn", []):
            edge_count += 1
            if dependency_ref not in known_refs:
                fail(f"dependency edge references an unknown component: {dependency_ref}")
    if edge_count == 0:
        fail("no dependency relationships were generated")

    properties = metadata.setdefault("properties", [])
    properties.extend(
        [
            {"name": "ci.branch", "value": branch},
            {"name": "ci.commit", "value": commit},
        ]
    )
    bom_path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    errors = sorted(
        validator.iter_errors(bom),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        fail(f"CI source metadata is invalid: {errors[0].message}")


if __name__ == "__main__":
    main()
