from __future__ import annotations

import json
import re
import tomllib
from scanners.traversal import iter_files
from pathlib import Path


DEPENDENCY_FILES = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "package.json": "node",
    "package-lock.json": "node",
}


def _constraint_type(constraint: str, version: str) -> str:
    if version:
        return "exact"
    value = constraint.strip()
    if value.startswith(("http://", "https://", "git+", "file:")):
        return "url"
    if value.startswith(("^", "~", ">", "<", "=")) or " || " in value or " - " in value:
        return "range"
    if value in ("", "*", "latest"):
        return "unresolved"
    return "tag-or-range"


def _parse_requirements(path: Path) -> list[dict[str, str]]:
    dependencies = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-", ";")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([<>=!~].*)?$", line.split("#", 1)[0].split(";", 1)[0].strip())
        if match:
            constraint = (match.group(2) or "").strip()
            version_match = re.fullmatch(r"==\s*([0-9][A-Za-z0-9_.+-]*)", constraint)
            version = version_match.group(1) if version_match else ""
            dependencies.append({"name": match.group(1), "constraint": constraint, "constraint_type": _constraint_type(constraint, version), "version": version})
    return dependencies


def _parse_package_json(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package.json must contain an object")
    dependencies = []
    for section in ("dependencies", "devDependencies"):
        if not isinstance(data.get(section, {}), dict):
            raise ValueError(f"{section} must contain an object")
        for name, constraint in data.get(section, {}).items():
            value = str(constraint)
            version_match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)", value)
            version = version_match.group(1) if version_match else ""
            dependencies.append({"name": name, "constraint": value, "constraint_type": _constraint_type(value, version), "version": version})
    return dependencies


def _parse_npm_lock(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("lockfileVersion") not in (2, 3):
        raise ValueError("Supported npm lockfile versions: 2 and 3")
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("Lockfile packages must be an object")
    dependencies = []
    for location, package in packages.items():
        if not location or "node_modules/" not in location:
            continue
        if not isinstance(package, dict):
            raise ValueError("Lockfile package entries must be objects")
        version = package.get("version", "")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version):
            continue
        name = package.get("name") or location.rsplit("node_modules/", 1)[1]
        dependencies.append({"name": name, "constraint": version, "constraint_type": "exact", "version": version})
    return dependencies


def scan_dependencies(root: Path, ignored_directories: set[str] | None = None) -> list[dict[str, object]]:
    """Inventory supported dependency manifests and report malformed files."""
    findings = []
    root = root.resolve()
    for manifest in iter_files(root, ignored_directories):
        manifest_name = manifest.name
        if manifest_name in DEPENDENCY_FILES:
            ecosystem = DEPENDENCY_FILES[manifest_name]
            try:
                if manifest_name == "requirements.txt":
                    dependencies = _parse_requirements(manifest)
                elif manifest_name == "package.json":
                    dependencies = _parse_package_json(manifest)
                elif manifest_name == "package-lock.json":
                    dependencies = _parse_npm_lock(manifest)
                else:
                    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
                    dependencies = []
                    for declaration in data.get("project", {}).get("dependencies", []):
                        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([0-9][A-Za-z0-9_.+-]*)", declaration)
                        version = match.group(2) if match else ""
                        dependencies.append({"name": match.group(1) if match else declaration, "constraint": declaration, "constraint_type": _constraint_type(declaration, version), "version": version})
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                findings.append({
                    "severity": "WARNING",
                    "rule": "Malformed dependency manifest",
                    "file": str(manifest.relative_to(root)),
                    "details": str(exc),
                })
                continue
            findings.append({
                "severity": "INFO",
                "rule": "Dependency inventory",
                "file": str(manifest.relative_to(root)),
                "ecosystem": ecosystem,
                "dependency_count": len(dependencies),
                "dependencies": [{**item, "ecosystem": "PyPI" if ecosystem == "python" else "npm", "manifest": str(manifest.relative_to(root)), "resolved": manifest_name == "package-lock.json"} for item in dependencies],
            })
    return findings


def reconcile_inventory(records: list[dict[str, object]]) -> list[dict[str, str]]:
    packages = [item for record in records for item in record.get("dependencies", [])]
    resolved = {(str(Path(item["manifest"]).parent), item["name"], item["ecosystem"]) for item in packages if item.get("resolved")}
    unique = {}
    for item in packages:
        key = (str(Path(item["manifest"]).parent), item["name"], item["ecosystem"])
        if not item.get("resolved") and key in resolved:
            continue
        unique.setdefault((item["name"], item["ecosystem"], item.get("version", "")), item)
    return list(unique.values())
