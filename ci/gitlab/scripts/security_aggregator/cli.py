#!/usr/bin/env python3
"""Unified Security Aggregator — CLI entry point.

Usage:
  python3 -m security_aggregator --project-dir /path/to/project
  python3 -m security_aggregator --apply-fixes --project-dir /path/to/project

Fix resolution uses NVD + Maven Central. OSV is not consulted.
"""
import argparse
import json
import os
import sys
import traceback
from datetime import datetime

from .aggregator import aggregate_findings, deduplicate_findings, resolve_fixes
from .apply import apply_fixes
from .reporter import generate_unified_report


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Unified Security Aggregator')
    p.add_argument('--project-dir', required=True)
    p.add_argument('--output-dir', default='security-reports')
    p.add_argument('--severity', default='HIGH,CRITICAL')
    p.add_argument('--offline', action='store_true')
    p.add_argument('--apply-fixes', action='store_true')
    return p.parse_args()


def _empty_reports(out_dir: str, err: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now().isoformat()
    for name, data in (
        ('unified-findings.json', {'total': 0, 'findings': [], 'generated_at': now, 'error': err}),
        ('remediation-plan.json', {'total': 0, 'remediations': [], 'generated_at': now, 'error': err}),
        ('summary.json', {'summary': {}, 'error': err}),
    ):
        with open(os.path.join(out_dir, name), 'w') as f:
            json.dump(data, f, indent=2)


def main() -> int:
    args = _parse_args()
    severity = [s.strip().upper() for s in args.severity.split(',')]
    print(f"Unified Security Aggregator | severity={severity} | offline={args.offline}\n")

    try:
        print("Step 1: Aggregating findings...")
        findings, sources, cdx_index = aggregate_findings(args.project_dir, severity)
        print(f"Total: {len(findings)} | {sources}\n")
    except Exception as exc:
        print(f"ERROR aggregating: {exc}")
        traceback.print_exc()
        _empty_reports(args.output_dir, str(exc))
        return 1

    try:
        print("Step 2: Deduplicating...")
        unique = deduplicate_findings(findings)
        print(f"Unique: {len(unique)}\n")
    except Exception as exc:
        print(f"ERROR deduplicating: {exc}")
        unique = findings

    remediations = []
    try:
        print("Step 3: Resolving fixes (NVD + Maven Central)...")
        remediations = resolve_fixes(unique, args.offline, cdx_index)
        actionable = [r for r in remediations if r.status == 'actionable']
        not_affected = [r for r in remediations if r.status == 'not-affected']
        no_fix = [r for r in remediations if r.status == 'no-fix']
        print(f"Actionable: {len(actionable)} | Safe: {len(not_affected)} | No fix: {len(no_fix)}")
        for rem in actionable:
            print(f"  {rem.package_name}: {rem.current_version} \u2192 {rem.fixed_version} "
                  f"[{rem.strategy}, risk={rem.risk_level}]")
        print()
    except Exception as exc:
        print(f"ERROR resolving fixes: {exc}")
        traceback.print_exc()

    try:
        print("Step 4: Generating reports...")
        generate_unified_report(unique, remediations, args.output_dir)
    except Exception as exc:
        print(f"ERROR generating reports: {exc}")
        _empty_reports(args.output_dir, str(exc))

    applied = 0
    if args.apply_fixes:
        print("\nStep 5: Applying fixes...")
        applied = apply_fixes(remediations, args.project_dir)
        print(f"Applied: {applied}")
        if applied > 0:
            with open(os.path.join(args.output_dir, '.fixes-applied'), 'w') as f:
                f.write(f"{applied}\n")

    actionable = [r for r in remediations if r.status == 'actionable']
    if unique:
        print(f"\nSECURITY: {len(unique)} CVEs | {len(actionable)} actionable | {applied} applied")
    else:
        print("\nNo security findings detected.")
    return 0


if __name__ == '__main__':
    sys.exit(main())

