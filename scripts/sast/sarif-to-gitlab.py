#!/usr/bin/env python3
"""Convert a SARIF file into a GitLab SAST report and apply a severity gate.

Usage:
    sarif-to-gitlab.py <input.sarif> <output.gl-sast-report.json> [scanner-id]

Behaviour / exit codes:
    0  SARIF parsed, GitLab SAST report written, no finding at a gated severity.
    2  SARIF missing or invalid -> the scanner produced no usable output. This is
       treated as a scan failure (a silent no-op must not pass as green). A report
       with scan.status="failure" is still written so GitLab shows the failure.
    3  Gate triggered: at least one finding at a severity listed in
       SAST_FAIL_SEVERITIES (default "CRITICAL,HIGH"). Set it empty to disable the
       gate (report-only mode).

The GitLab severity of each finding is derived from the SARIF `security-severity`
property (CVSS, authoritative when present) and otherwise from the SARIF `level`.
"""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "15.0.6"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _sev_from_cvss(value):
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _sev_from_level(level):
    return {
        "error": "High",
        "warning": "Medium",
        "note": "Low",
        "none": "Info",
    }.get((level or "warning").lower(), "Medium")


def _write_report(path, scanner_id, scanner_name, vulnerabilities, status):
    scanner = {
        "id": scanner_id,
        "name": scanner_name,
        "version": "unknown",
        "vendor": {"name": scanner_name},
    }
    report = {
        "version": SCHEMA_VERSION,
        "scan": {
            "analyzer": {
                "id": "adorsys-sarif-to-gitlab",
                "name": "adorsys SARIF to GitLab SAST",
                "version": "1.0.0",
                "vendor": {"name": "adorsys"},
            },
            "scanner": scanner,
            "type": "sast",
            "start_time": _now(),
            "end_time": _now(),
            "status": status,
        },
        "vulnerabilities": vulnerabilities,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def main(argv):
    if len(argv) < 3:
        print("usage: sarif-to-gitlab.py <input.sarif> <output.json> [scanner-id]", file=sys.stderr)
        return 2
    sarif_path, out_path = argv[1], argv[2]
    scanner_hint = argv[3] if len(argv) > 3 else ""

    fail_set = {
        s.strip().upper()
        for s in os.environ.get("SAST_FAIL_SEVERITIES", "CRITICAL,HIGH").split(",")
        if s.strip()
    }

    # Guard: a missing or unparseable SARIF means the scanner did not produce
    # usable output (crash, bad config, swallowed error). Fail instead of passing.
    try:
        with open(sarif_path, encoding="utf-8") as handle:
            sarif = json.load(handle)
        runs = sarif.get("runs")
        if not isinstance(runs, list):
            raise ValueError("SARIF has no 'runs' array")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read SARIF '{sarif_path}': {exc}", file=sys.stderr)
        _write_report(out_path, scanner_hint or "sast", scanner_hint or "SAST", [], "failure")
        return 2

    vulnerabilities = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    scanner_id = scanner_hint or "sast"
    scanner_name = scanner_hint or "SAST"

    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        if not scanner_hint and driver.get("name"):
            scanner_name = driver["name"]
            scanner_id = driver["name"].lower().replace(" ", "-")
        rules = {}
        for rule in driver.get("rules") or []:
            rules[rule.get("id")] = rule

        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "unknown"
            rule = rules.get(rule_id, {})
            message = (result.get("message") or {}).get("text") or rule_id

            cvss = (result.get("properties") or {}).get("security-severity")
            if cvss is None:
                cvss = (rule.get("properties") or {}).get("security-severity")
            severity = _sev_from_cvss(cvss)
            if severity is None:
                severity = _sev_from_level(result.get("level") or rule.get("defaultConfiguration", {}).get("level"))
            counts[severity] = counts.get(severity, 0) + 1

            location = {"file": "unknown", "start_line": 1}
            locations = result.get("locations") or []
            if locations:
                phys = (locations[0].get("physicalLocation") or {})
                uri = (phys.get("artifactLocation") or {}).get("uri")
                region = phys.get("region") or {}
                if uri:
                    location["file"] = uri
                if region.get("startLine"):
                    location["start_line"] = region["startLine"]
                if region.get("endLine"):
                    location["end_line"] = region["endLine"]

            fingerprint = hashlib.sha256(
                f"{scanner_id}:{rule_id}:{location['file']}:{location.get('start_line')}:{message}".encode()
            ).hexdigest()

            vulnerabilities.append({
                "id": fingerprint,
                "category": "sast",
                "name": rule_id,
                "message": message[:255],
                "description": message,
                "severity": severity,
                "scanner": {"id": scanner_id, "name": scanner_name},
                "location": location,
                "identifiers": [{
                    "type": f"{scanner_id}_rule_id",
                    "name": rule_id,
                    "value": str(rule_id),
                }],
            })

    _write_report(out_path, scanner_id, scanner_name, vulnerabilities, "success")

    summary = ", ".join(f"{k}={counts[k]}" for k in ("Critical", "High", "Medium", "Low", "Info"))
    print(f"{scanner_name}: {len(vulnerabilities)} finding(s) [{summary}]", file=sys.stderr)

    gating = sorted(sev for sev in fail_set if counts.get(sev.capitalize(), 0) > 0)
    if gating:
        print(
            f"ERROR: SAST gate failed — {scanner_name} reported finding(s) at: {', '.join(gating)} "
            f"(gated severities: {', '.join(sorted(fail_set))}).",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
