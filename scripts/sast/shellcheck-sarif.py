#!/usr/bin/env python3
import json
import os

in_file = os.environ.get("SAST_IN", "shellcheck.json")
out_file = os.environ.get("SAST_OUT", "shellcheck.sarif")

sarif = {
    "version": "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "ShellCheck", "informationUri": "https://www.shellcheck.net/", "rules": []}}, "results": []}],
}

try:
    with open(in_file) as f:
        comments = json.load(f).get("comments", [])
except Exception:
    comments = []

rules = {}
for c in comments:
    rule_id = "SC%04d" % c.get("code", 0)
    if rule_id not in rules:
        rules[rule_id] = {"id": rule_id, "name": rule_id, "shortDescription": {"text": c.get("message", "")}}
    sarif["runs"][0]["results"].append({
        "ruleId": rule_id,
        "level": "warning" if c.get("level") == "info" else c.get("level", "warning"),
        "message": {"text": c.get("message", "")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": c.get("file", "")}, "region": {"startLine": c.get("line", 1)}}}],
    })

sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
with open(out_file, "w") as f:
    json.dump(sarif, f, indent=2)
