import json
import os
import re


def find_dockerfiles(project_dir: str) -> list[str]:
    """Find all Dockerfile files in the project."""
    dockerfiles = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            if f.startswith('Dockerfile') or f == 'Dockerfile':
                dockerfiles.append(os.path.join(root, f))
    return dockerfiles


def find_package_json_files(project_dir: str) -> list[str]:
    """Find all package.json files in the project."""
    package_files = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules' and d != 'dist']
        if 'package.json' in files:
            package_files.append(os.path.join(root, 'package.json'))
    return package_files


def apply_package_json_version(package_json_path: str, package_name: str, new_version: str) -> bool:
    """Update an npm package version in package.json."""
    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        updated = False
        for dep_section in ['dependencies', 'devDependencies', 'peerDependencies', 'resolutions']:
            deps = data.get(dep_section, {})
            if package_name in deps:
                old_version = deps[package_name]
                if old_version != new_version:
                    prefix_match = re.match(r'^([\^~>=<]+)', str(old_version))
                    prefix = prefix_match.group(1) if prefix_match else ''
                    applied_version = f"{prefix}{new_version}" if prefix else new_version
                    deps[package_name] = applied_version
                    updated = True
                    print(f"Updated {package_name} from {old_version} to {applied_version} in {package_json_path} [{dep_section}]")

        if updated:
            with open(package_json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.write('\n')
            return True
        return False
    except Exception as e:
        print(f"Error updating {package_json_path}: {e}")
        return False


def apply_dockerfile_version(dockerfile_path: str, image_name: str, new_tag: str) -> bool:
    """Update a Docker image tag in Dockerfile."""
    try:
        with open(dockerfile_path, 'r') as f:
            content = f.read()

        pattern = rf'(FROM\s+){re.escape(image_name)}(:[\w.-]+)?(\s+AS\s+\w+)?'

        def replace_tag(match):
            prefix = match.group(1)
            existing_tag = match.group(2) or ''
            alias = match.group(3) or ''
            return f"{prefix}{image_name}:{new_tag}{alias}"

        new_content, count = re.subn(pattern, replace_tag, content)

        if count > 0:
            with open(dockerfile_path, 'w') as f:
                f.write(new_content)
            print(f"Updated {image_name} to {new_tag} in {dockerfile_path}")
            return True
        return False
    except Exception as e:
        print(f"Error updating {dockerfile_path}: {e}")
        return False