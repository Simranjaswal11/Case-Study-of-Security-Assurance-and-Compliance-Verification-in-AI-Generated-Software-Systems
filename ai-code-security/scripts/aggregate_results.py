"""
aggregate_results.py
--------------------
Merges Bandit, Semgrep, and pip-audit results.
Deduplicates findings from the same file/line detected by multiple scanners.
Produces: results/aggregated_results.csv

Usage:
    python scripts/aggregate_results.py
"""

import os
import json
import csv

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "../results")

BANDIT_FILE  = os.path.join(RESULTS_DIR, "bandit_results.json")
SEMGREP_FILE = os.path.join(RESULTS_DIR, "semgrep_results.json")
PIPAUDIT_FILE = os.path.join(RESULTS_DIR, "pipaudit_results.json")
OUTPUT_CSV   = os.path.join(RESULTS_DIR, "aggregated_results.csv")
OUTPUT_SUMMARY = os.path.join(RESULTS_DIR, "summary.json")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}

OWASP_LABELS = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "SSRF",
}


def load_json(path):
    if not os.path.exists(path):
        print(f"  [SKIP] {path} not found.")
        return []
    with open(path) as f:
        return json.load(f)


def normalize_bandit(findings):
    rows = []
    for f in findings:
        rows.append({
            "artifact_id": f.get("artifact_id", ""),
            "tool_source": f.get("tool_source", ""),
            "prompt_id": f.get("prompt_id", ""),
            "scanner": "bandit",
            "rule": f.get("test_id", ""),
            "description": f.get("test_name", ""),
            "owasp_category": f.get("owasp_category", "UNKNOWN"),
            "severity": f.get("severity", "").upper(),
            "line": str(f.get("line_number", "")),
            "snippet": f.get("code_snippet", "")[:120],
            "filename": f.get("filename", ""),
            "dedup_key": f"{f.get('artifact_id','')}|{f.get('line_number','')}|{f.get('test_id','')}",
        })
    return rows


def normalize_semgrep(findings):
    rows = []
    for f in findings:
        rows.append({
            "artifact_id": f.get("artifact_id", ""),
            "tool_source": f.get("tool_source", ""),
            "prompt_id": f.get("prompt_id", ""),
            "scanner": "semgrep",
            "rule": f.get("rule_id", ""),
            "description": f.get("message", ""),
            "owasp_category": f.get("owasp_category", "UNKNOWN"),
            "severity": f.get("severity", "").upper(),
            "line": str(f.get("line_start", "")),
            "snippet": f.get("code_snippet", "")[:120],
            "filename": f.get("filename", ""),
            "dedup_key": f"{f.get('artifact_id','')}|{f.get('line_start','')}|{f.get('rule_id','')}",
        })
    return rows


def normalize_pipaudit(findings):
    rows = []
    for f in findings:
        rows.append({
            "artifact_id": f.get("artifact_id", ""),
            "tool_source": f.get("tool_source", ""),
            "prompt_id": f.get("prompt_id", ""),
            "scanner": "pip-audit",
            "rule": f.get("vuln_id", ""),
            "description": f"{f.get('package','')} {f.get('installed_version','')}: {f.get('description','')}",
            "owasp_category": "A06",
            "severity": f.get("severity", "HIGH").upper(),
            "line": "",
            "snippet": "",
            "filename": "",
            "dedup_key": f"{f.get('artifact_id','')}|{f.get('vuln_id','')}",
        })
    return rows


def deduplicate(rows):
    """
    Keep one finding per (artifact, line, rule) combination.
    Where duplicates exist, keep the one with the highest severity.
    """
    seen = {}
    for row in rows:
        key = row["dedup_key"]
        if key not in seen:
            seen[key] = row
        else:
            existing_rank = SEVERITY_RANK.get(seen[key]["severity"], 0)
            new_rank = SEVERITY_RANK.get(row["severity"], 0)
            if new_rank > existing_rank:
                seen[key] = row
    return list(seen.values())


def compute_summary(unique_rows):
    """Compute per-tool and per-OWASP-category counts."""
    by_tool = {}
    by_owasp = {}
    critical_high_by_tool = {}

    for row in unique_rows:
        tool = row["tool_source"]
        cat = row["owasp_category"]
        sev = row["severity"]

        by_tool[tool] = by_tool.get(tool, 0) + 1
        by_owasp[cat] = by_owasp.get(cat, 0) + 1

        if sev in ("CRITICAL", "HIGH"):
            critical_high_by_tool[tool] = critical_high_by_tool.get(tool, 0) + 1

    # Artifact counts per tool (30 prompts each)
    artifacts_per_tool = 30
    cvr = {}
    for tool, count in critical_high_by_tool.items():
        cvr[tool] = f"{round(count / artifacts_per_tool * 100, 1)}%"

    return {
        "total_unique_vulnerabilities": len(unique_rows),
        "by_tool": by_tool,
        "by_owasp_category": {
            k: {"count": v, "label": OWASP_LABELS.get(k, k)}
            for k, v in sorted(by_owasp.items())
        },
        "critical_high_count_by_tool": critical_high_by_tool,
        "critical_vulnerability_rate_by_tool": cvr,
    }


def run():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("Loading results...")
    bandit_raw   = load_json(BANDIT_FILE)
    semgrep_raw  = load_json(SEMGREP_FILE)
    pipaudit_raw = load_json(PIPAUDIT_FILE)

    print(f"  Bandit:   {len(bandit_raw)} findings")
    print(f"  Semgrep:  {len(semgrep_raw)} findings")
    print(f"  pip-audit: {len(pipaudit_raw)} findings")

    all_rows = (
        normalize_bandit(bandit_raw) +
        normalize_semgrep(semgrep_raw) +
        normalize_pipaudit(pipaudit_raw)
    )
    print(f"\nTotal before deduplication: {len(all_rows)}")

    unique_rows = deduplicate(all_rows)
    print(f"Total after deduplication:  {len(unique_rows)}")

    # Write CSV
    fieldnames = [
        "artifact_id", "tool_source", "prompt_id", "scanner",
        "rule", "description", "owasp_category", "severity",
        "line", "snippet", "filename",
    ]
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(unique_rows)
    print(f"\nAggregated results saved to: {OUTPUT_CSV}")

    # Write summary
    summary = compute_summary(unique_rows)
    with open(OUTPUT_SUMMARY, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary saved to: {OUTPUT_SUMMARY}")

    # Print summary table
    print("\n── OWASP Category Breakdown ──────────────────────")
    print(f"{'Category':<6} {'Label':<45} {'Count':>5}  {'%':>6}")
    print("-" * 65)
    total = summary["total_unique_vulnerabilities"]
    for cat, info in summary["by_owasp_category"].items():
        pct = round(info["count"] / total * 100, 1) if total else 0
        print(f"{cat:<6} {info['label']:<45} {info['count']:>5}  {pct:>5.1f}%")

    print("\n── Critical Vulnerability Rate by Tool ───────────")
    for tool, rate in summary["critical_vulnerability_rate_by_tool"].items():
        print(f"  {tool:<20} CVR = {rate}")


if __name__ == "__main__":
    run()
