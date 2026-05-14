"""
run_bandit.py
-------------
Runs Bandit (Python SAST) on every artifact in artifacts/<tool>/<prompt_id>.py
Outputs: results/bandit_results.json

Requirements:
    pip install bandit

Usage:
    python scripts/run_bandit.py
"""

import os
import json
import subprocess

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "../artifacts")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "../results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "bandit_results.json")

# OWASP Top 10 (2021) mapping from Bandit test IDs / CWE numbers
# Extend this mapping as needed based on Bandit's rule set
BANDIT_OWASP_MAP = {
    "B105": "A07",   # Hardcoded password
    "B106": "A07",   # Hardcoded password (funcarg)
    "B107": "A07",   # Hardcoded password (default)
    "B501": "A02",   # Weak SSL/TLS
    "B502": "A02",   # SSL with no verification
    "B503": "A02",   # SSL with bad version
    "B504": "A02",   # SSL with bad defaults
    "B505": "A02",   # Weak cryptographic key
    "B303": "A02",   # MD5/SHA1 usage
    "B304": "A02",   # Insecure cipher
    "B305": "A02",   # Insecure cipher mode
    "B306": "A02",   # mktemp (not crypto but sensitive)
    "B324": "A02",   # MD5/SHA1 in hashlib
    "B608": "A03",   # SQL injection
    "B601": "A03",   # Paramiko shell injection
    "B602": "A03",   # subprocess with shell=True
    "B603": "A03",   # subprocess without shell (still tracked)
    "B604": "A03",   # Function call with shell=True
    "B605": "A03",   # os.system
    "B606": "A03",   # os.spawn (no args)
    "B607": "A03",   # os.spawn (partial path)
    "B611": "A03",   # Django RawSQL
    "B703": "A03",   # Django extra used with format
    "B704": "A03",   # Jinja2 autoescape disabled
    "B201": "A05",   # Flask debug mode
    "B401": "A05",   # Import telnetlib (insecure protocol)
    "B322": "A05",   # Python 2 input()
    "B301": "A08",   # Pickle usage (deserialization)
    "B302": "A08",   # Marshal loads
    "B403": "A08",   # Import pickle
    "B404": "A08",   # Import subprocess (flagged)
    "B320": "A08",   # XML with lxml
    "B405": "A08",   # Import xml.etree (unsafe XML)
    "B406": "A08",   # Import xml.sax
    "B407": "A08",   # Import xml.expat
    "B408": "A08",   # Import xml.minidom
    "B409": "A08",   # Import xml.pulldom
    "B411": "A08",   # Import xmlrpclib
    "B101": "A05",   # Assert used
    "B110": "A09",   # Try/except/pass (swallowed error)
    "B112": "A09",   # Try/except/continue
}


def collect_artifacts():
    """Walk artifacts directory and return list of (tool, prompt_id, filepath)."""
    entries = []
    for tool in os.listdir(ARTIFACTS_DIR):
        tool_dir = os.path.join(ARTIFACTS_DIR, tool)
        if not os.path.isdir(tool_dir):
            continue
        for fname in sorted(os.listdir(tool_dir)):
            if fname.endswith(".py"):
                pid = fname.replace(".py", "")
                fpath = os.path.join(tool_dir, fname)
                entries.append((tool, pid, fpath))
    return entries


def run_bandit_on_file(filepath: str) -> list:
    """Run Bandit on a single file and return list of finding dicts."""
    cmd = [
        "bandit",
        "-f", "json",
        "-l",           # report all levels
        "-i",           # report all confidence levels
        filepath,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        # Bandit exits non-zero when findings exist — that's normal
        output = result.stdout
        if not output.strip():
            return []
        data = json.loads(output)
        return data.get("results", [])
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {filepath}")
        return []
    except json.JSONDecodeError:
        print(f"  [JSON ERROR] Could not parse Bandit output for {filepath}")
        return []
    except FileNotFoundError:
        print("  [ERROR] Bandit not found. Install with: pip install bandit")
        return []


def map_owasp(test_id: str) -> str:
    return BANDIT_OWASP_MAP.get(test_id, "UNKNOWN")


def run():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    artifacts = collect_artifacts()

    if not artifacts:
        print("[ERROR] No artifacts found. Run generate_code.py first.")
        return

    print(f"Running Bandit on {len(artifacts)} artifacts...\n")
    all_findings = []

    for tool, pid, filepath in artifacts:
        print(f"  Scanning [{tool}][{pid}] ...", end=" ")
        raw_findings = run_bandit_on_file(filepath)

        for f in raw_findings:
            all_findings.append({
                "artifact_id": f"{tool}_{pid}",
                "tool_source": tool,
                "prompt_id": pid,
                "scanner": "bandit",
                "test_id": f.get("test_id", ""),
                "test_name": f.get("test_name", ""),
                "cwe": f.get("issue_cwe", {}).get("id", "") if isinstance(f.get("issue_cwe"), dict) else "",
                "owasp_category": map_owasp(f.get("test_id", "")),
                "severity": f.get("issue_severity", ""),
                "confidence": f.get("issue_confidence", ""),
                "line_number": f.get("line_number", ""),
                "code_snippet": f.get("code", "").strip(),
                "filename": filepath,
            })

        print(f"{len(raw_findings)} findings")

    with open(OUTPUT_FILE, "w") as out:
        json.dump(all_findings, out, indent=2)

    print(f"\nBandit scan complete. {len(all_findings)} total findings.")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run()
