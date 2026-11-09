#!/usr/bin/env python3
"""Decorate and validate CycloneDX 1.6 Maven reactor BOMs."""

import hashlib
import html
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema


def fail(message):
    raise SystemExit(f"SBOM validation failed: {message}")


def schema_validator(schema, schema_path):
    store = {schema["$id"]: schema}
    for filename, digest in (
        ("spdx.schema.json", "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"),
        ("jsf-0.82.schema.json", "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"),
    ):
        path = schema_path.parent / filename
        try:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                fail(f"schema checksum mismatch: {path}")
            companion = json.loads(data)
        except (OSError, json.JSONDecodeError) as error:
            fail(f"cannot load schema {path}: {error}")
        store[companion["$id"]] = companion

    def reject_remote_schema(uri):
        fail(f"schema reference is not bundled locally: {uri}")

    # RefResolver supports the distro jsonschema version installed by the CI job.
    resolver = jsonschema.RefResolver.from_schema(
        schema,
        store=store,
        handlers={"http": reject_remote_schema, "https": reject_remote_schema},
    )
    return jsonschema.Draft7Validator(schema, resolver=resolver)


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


def render_html(bom, branch, commit):
    def escape(value):
        return html.escape(str(value))

    root = bom["metadata"]["component"]
    components = [root, *bom["components"]]
    anchors = {component["bom-ref"]: f"component-{index}" for index, component in enumerate(components)}

    def component_link(ref):
        return f'<a href="#{anchors[ref]}">{escape(ref)}</a>'

    rows = []
    for component in components:
        licenses = []
        for choice in component.get("licenses", []):
            license_info = choice.get("license", {})
            licenses.append(choice.get("expression") or license_info.get("id") or license_info.get("name", ""))
        values = (
            component.get("group", ""),
            component["name"],
            component.get("version", ""),
            component["type"],
            component.get("scope", ""),
            "; ".join(licenses) or "Not specified",
            component.get("purl", ""),
            component["bom-ref"],
        )
        cells = "".join(f"<td>{escape(value)}</td>" for value in values)
        rows.append(f'<tr id="{anchors[component["bom-ref"]]}">{cells}</tr>')

    relationships = []
    edge_count = 0
    for dependency in bom["dependencies"]:
        targets = dependency.get("dependsOn", [])
        edge_count += len(targets)
        links = "<ul>" + "".join(f"<li>{component_link(ref)}</li>" for ref in targets) + "</ul>"
        relationships.append(
            f"<tr><td>{component_link(dependency['ref'])}</td>"
            f"<td>{links if targets else 'No dependencies recorded'}</td></tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>SBOM inventory - {escape(root['name'])}</title>
<style>
body {{ font: 1rem system-ui, sans-serif; margin: 2rem; color: #17212b; background: #fff; }}
a {{ color: #0645ad; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccd3da; padding: .5rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #edf2f7; }}
tr:target {{ background: #fff3cc; }}
.table-scroll {{ overflow-x: auto; }}
dt {{ font-weight: bold; }}
dd {{ margin-bottom: .5rem; overflow-wrap: anywhere; }}
@media print {{ body {{ margin: 0; }} }}
</style>
</head>
<body>
<h1>SBOM inventory</h1>
<p>Inventory only: this is not an OWASP vulnerability scan. The CycloneDX JSON is the authoritative SBOM.</p>
<dl>
<dt>Project</dt><dd>{escape(root['name'])}</dd>
<dt>Version</dt><dd>{escape(root.get('version', 'Not specified'))}</dd>
<dt>Branch / ref</dt><dd>{escape(branch)}</dd>
<dt>Source commit</dt><dd>{escape(commit)}</dd>
<dt>Format</dt><dd>CycloneDX {escape(bom['specVersion'])}</dd>
<dt>Generated timestamp</dt><dd>{escape(bom['metadata'].get('timestamp', 'Not specified'))}</dd>
<dt>Dependency components</dt><dd>{len(bom['components'])}</dd>
<dt>Dependency relationships</dt><dd>{edge_count}</dd>
</dl>
<nav><a href="#components">Components</a> | <a href="#relationships">Dependency relationships</a></nav>
<h2 id="components">Components (including root project)</h2>
<div class="table-scroll"><table>
<thead><tr><th>Group</th><th>Name</th><th>Version</th><th>Type</th><th>Scope</th><th>Licenses</th>
<th>Package URL</th><th>BOM reference</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></div>
<h2 id="relationships">Dependency relationships</h2>
<div class="table-scroll"><table>
<thead><tr><th>Component</th><th>Depends on</th></tr></thead>
<tbody>{''.join(relationships)}</tbody>
</table></div>
</body>
</html>
"""


def main():
    if len(sys.argv) != 6:
        fail("usage: validate-maven-sbom.py BOM SCHEMA POM BRANCH COMMIT")

    bom_path, schema_path, pom_path = map(Path, sys.argv[1:4])
    branch, commit = sys.argv[4:6]
    report_path = bom_path.with_suffix(".html")
    report_path.unlink(missing_ok=True)
    if not bom_path.is_file() or bom_path.stat().st_size == 0:
        fail(f"BOM is missing or empty: {bom_path}")
    try:
        bom = json.loads(bom_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(str(error))

    validator = schema_validator(schema, schema_path)
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
    try:
        report_path.write_text(render_html(bom, branch, commit), encoding="utf-8")
    except OSError as error:
        fail(f"cannot write HTML inventory {report_path}: {error}")


if __name__ == "__main__":
    main()
