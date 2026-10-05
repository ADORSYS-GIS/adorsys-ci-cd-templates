#!/usr/bin/env python3
"""Render a SARIF 2.1.0 file as a human-readable, self-contained HTML report.

Usage: sarif-to-html.py <input.sarif> <output.html>
Standard library only, so it runs on any image that has python3.
"""
import html
import json
import sys

LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


def load_rows(sarif):
    rows = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {}) or {}
        tool = driver.get("name", "SAST")
        rule_level = {}
        for rule in driver.get("rules", []) or []:
            lvl = (rule.get("defaultConfiguration", {}) or {}).get("level")
            if lvl:
                rule_level[rule.get("id")] = lvl
        for res in run.get("results", []) or []:
            if any(suppression.get("status") in (None, "accepted") for suppression in res.get("suppressions") or []):
                continue
            rule_id = res.get("ruleId", "")
            level = res.get("level") or rule_level.get(rule_id, "warning")
            message = (res.get("message", {}) or {}).get("text", "")
            uri = ""
            line = ""
            locations = res.get("locations", []) or []
            if locations:
                phys = (locations[0] or {}).get("physicalLocation", {}) or {}
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine", "")
            rows.append((tool, level, rule_id, uri, str(line), message))
    return rows


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: sarif-to-html.py <input.sarif> <output.html>")
    in_file, out_file = sys.argv[1], sys.argv[2]
    try:
        with open(in_file) as fh:
            sarif = json.load(fh)
    except Exception:
        sarif = {}

    rows = load_rows(sarif)
    rows.sort(key=lambda r: (LEVEL_ORDER.get(r[1], 9), r[0], r[3]))

    tool = rows[0][0] if rows else "SAST"
    counts = {}
    for _, level, *_ in rows:
        counts[level] = counts.get(level, 0) + 1
    summary = ", ".join(f"{counts[k]} {k}" for k in sorted(counts)) or "no findings"

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{html.escape(tool)} SAST report</title><style>",
        "body{font-family:system-ui,Arial,sans-serif;margin:1.5rem;color:#1b1b1b}",
        "h1{font-size:1.3rem}.sum{margin:.4rem 0 1rem;color:#444}",
        "table{border-collapse:collapse;width:100%}",
        "th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.9rem}",
        "th{background:#f3f3f3}tr:nth-child(even){background:#fafafa}",
        ".error{color:#b00020;font-weight:600}.warning{color:#9a6700}.note{color:#0b6}.none{color:#666}",
        "code{white-space:pre-wrap;word-break:break-word}",
        "</style></head><body>",
        f"<h1>{html.escape(tool)} SAST report</h1>",
        f"<p class='sum'>{html.escape(summary)}</p>",
    ]
    if rows:
        parts.append(
            "<table><thead><tr><th>Severity</th><th>Rule</th>"
            "<th>File</th><th>Line</th><th>Message</th></tr></thead><tbody>"
        )
        for _, level, rule_id, uri, line, message in rows:
            css = level if level in LEVEL_ORDER else "none"
            parts.append(
                "<tr>"
                f"<td class='{html.escape(css)}'>{html.escape(level)}</td>"
                f"<td>{html.escape(rule_id)}</td>"
                f"<td><code>{html.escape(uri)}</code></td>"
                f"<td>{html.escape(line)}</td>"
                f"<td>{html.escape(message)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append("<p>No findings.</p>")
    parts.append("</body></html>")

    with open(out_file, "w") as fh:
        fh.write("\n".join(parts))


if __name__ == "__main__":
    main()
