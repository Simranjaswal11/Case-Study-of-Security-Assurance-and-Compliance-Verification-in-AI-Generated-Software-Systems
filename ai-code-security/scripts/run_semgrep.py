"""
run_semgrep.py
--------------
Runs Semgrep with the OWASP Top 10 community ruleset on all artifacts.
Outputs: results/semgrep_results.json

Requirements:
    pip install semgrep

Usage:
    python scripts/run_semgrep.py

Note: Semgrep will download the OWASP Top 10 ruleset on first run.
      Requires internet access on first execution.
"""

import os
import json
import subprocess

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "../artifacts")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "../results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "semgrep_results.json")

# Semgrep OWASP ruleset — downloads automatically
SEMGREP_CONFIG = "p/owasp-top-ten"


def collect_tool_dirs():
    """Return list of (tool_name, tool_dir) tuples."""
    dirs = []
    for tool in os.listdir(ARTIFACTS_DIR):
        tool_dir = os.path.join(ARTIFACTS_DIR, tool)
        if os.path.isdir(tool_dir):
            dirs.append((tool, tool_dir))
    return dirs


def run_semgrep_on_dir(tool: str, tool_dir: str) -> list:
    """Run Semgrep on a directory of artifacts and return parsed findings."""
    cmd = [
        "semgrep",
        "--config", SEMGREP_CONFIG,
        "--json",
        "--quiet",
        tool_dir,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout
        if not output.strip():
            return []
        data = json.loads(output)
        results = data.get("results", [])

        findings = []
        for r in results:
            filepath = r.get("path", "")
            fname = os.path.basename(filepath)
            pid = fname.replace(".py", "")

            # Extract OWASP category from rule metadata if present
            metadata = r.get("extra", {}).get("metadata", {})
            owasp_cat = ""
            if isinstance(metadata.get("owasp"), list) and metadata["owasp"]:
                owasp_cat = metadata["owasp"][0][:3]   # e.g. "A03"
            elif isinstance(metadata.get("owasp"), str):
                owasp_cat = metadata["owasp"][:3]

            findings.append({
                "artifact_id": f"{tool}_{pid}",
                "tool_source": tool,
                "prompt_id": pid,
                "scanner": "semgrep",
                "rule_id": r.get("check_id", ""),
                "owasp_category": owasp_cat,
                "severity": r.get("extra", {}).get("severity", "").upper(),
                "message": r.get("extra", {}).get("message", ""),
                "line_start": r.get("start", {}).get("line", ""),
                "line_end": r.get("end", {}).get("line", ""),
                "code_snippet": r.get("extra", {}).get("lines", "").strip(),
                "filename": filepath,
            })
        return findings

    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] Semgrep on {tool_dir}")
        return []
    except json.JSONDecodeError:
        print(f"  [JSON ERROR] Could not parse Semgrep output for {tool_dir}")
        return []
    except FileNotFoundError:
        print("  [ERROR] Semgrep not found. Install with: pip install semgrep")
        return []


def run():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    tool_dirs = collect_tool_dirs()

    if not tool_dirs:
        print("[ERROR] No artifact directories found. Run generate_code.py first.")
        return

    print(f"Running Semgrep (config: {SEMGREP_CONFIG}) on {len(tool_dirs)} tool directories...\n")
    all_findings = []

    for tool, tool_dir in tool_dirs:
        print(f"  Scanning [{tool}] directory...", end=" ")
        findings = run_semgrep_on_dir(tool, tool_dir)
        all_findings.extend(findings)
        print(f"{len(findings)} findings")

    with open(OUTPUT_FILE, "w") as out:
        json.dump(all_findings, out, indent=2)

    print(f"\nSemgrep scan complete. {len(all_findings)} total findings.")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run()
