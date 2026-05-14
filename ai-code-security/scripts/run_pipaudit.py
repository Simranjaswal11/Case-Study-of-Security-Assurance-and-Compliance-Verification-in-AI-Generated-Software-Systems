"""
run_pipaudit.py
---------------
Extracts third-party imports from all artifacts, resolves them to package names,
and checks for known CVEs using pip-audit.
Outputs: results/pipaudit_results.json

Requirements:
    pip install pip-audit

Usage:
    python scripts/run_pipaudit.py
"""

import os
import ast
import json
import subprocess
import tempfile

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "../artifacts")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "../results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "pipaudit_results.json")

# Mapping from import name → PyPI package name (common discrepancies)
IMPORT_TO_PACKAGE = {
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "sqlalchemy": "sqlalchemy",
    "requests": "requests",
    "cryptography": "cryptography",
    "jwt": "pyjwt",
    "pyjwt": "pyjwt",
    "paramiko": "paramiko",
    "yaml": "pyyaml",
    "pyyaml": "pyyaml",
    "lxml": "lxml",
    "pymysql": "pymysql",
    "psycopg2": "psycopg2",
    "boto3": "boto3",
    "aiohttp": "aiohttp",
    "httpx": "httpx",
    "starlette": "starlette",
    "jinja2": "jinja2",
    "werkzeug": "werkzeug",
    "itsdangerous": "itsdangerous",
    "click": "click",
    "celery": "celery",
    "redis": "redis",
    "pymongo": "pymongo",
    "bcrypt": "bcrypt",
    "passlib": "passlib",
    "oauthlib": "oauthlib",
}

# Standard library modules to ignore
STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "hashlib", "hmac",
    "sqlite3", "logging", "pathlib", "subprocess", "threading", "socket",
    "http", "urllib", "email", "base64", "struct", "io", "csv",
    "collections", "itertools", "functools", "typing", "abc", "copy",
    "math", "random", "secrets", "string", "textwrap", "traceback",
    "uuid", "warnings", "pickle", "marshal", "shelve", "tempfile",
    "shutil", "glob", "fnmatch", "xml", "html", "configparser", "enum",
}


def extract_imports(filepath: str) -> set:
    """Parse a Python file and return all imported top-level module names."""
    imports = set()
    try:
        with open(filepath, "r", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0].lower())
    except SyntaxError:
        pass  # Generated code may have syntax errors; skip silently
    return imports - STDLIB


def resolve_packages(imports: set) -> set:
    """Map import names to PyPI package names where known."""
    packages = set()
    for imp in imports:
        pkg = IMPORT_TO_PACKAGE.get(imp)
        if pkg:
            packages.add(pkg)
    return packages


def run_pipaudit(packages: set) -> list:
    """Write a requirements.txt and run pip-audit against it."""
    if not packages:
        return []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="req_"
    ) as tmp:
        for pkg in packages:
            tmp.write(pkg + "\n")
        tmp_path = tmp.name

    try:
        cmd = ["pip-audit", "-r", tmp_path, "-f", "json", "--no-deps"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout
        if not output.strip():
            return []
        data = json.loads(output)
        return data.get("dependencies", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [pip-audit error] {e}")
        return []
    finally:
        os.unlink(tmp_path)


def run():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_findings = []

    for tool in os.listdir(ARTIFACTS_DIR):
        tool_dir = os.path.join(ARTIFACTS_DIR, tool)
        if not os.path.isdir(tool_dir):
            continue

        for fname in sorted(os.listdir(tool_dir)):
            if not fname.endswith(".py"):
                continue
            pid = fname.replace(".py", "")
            fpath = os.path.join(tool_dir, fname)

            imports = extract_imports(fpath)
            packages = resolve_packages(imports)

            if not packages:
                continue

            print(f"  pip-audit [{tool}][{pid}] packages: {packages} ...", end=" ")
            vuln_deps = run_pipaudit(packages)

            for dep in vuln_deps:
                for vuln in dep.get("vulns", []):
                    all_findings.append({
                        "artifact_id": f"{tool}_{pid}",
                        "tool_source": tool,
                        "prompt_id": pid,
                        "scanner": "pip-audit",
                        "package": dep.get("name", ""),
                        "installed_version": dep.get("version", ""),
                        "vuln_id": vuln.get("id", ""),
                        "description": vuln.get("description", ""),
                        "fix_versions": vuln.get("fix_versions", []),
                        "owasp_category": "A06",   # Vulnerable and Outdated Components
                        "severity": "HIGH",
                    })

            count = sum(len(d.get("vulns", [])) for d in vuln_deps)
            print(f"{count} CVEs found")

    with open(OUTPUT_FILE, "w") as out:
        json.dump(all_findings, out, indent=2)

    print(f"\npip-audit complete. {len(all_findings)} CVE findings.")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run()
