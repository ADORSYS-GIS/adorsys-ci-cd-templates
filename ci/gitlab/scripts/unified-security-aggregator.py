#!/usr/bin/env python3
"""Unified Security Aggregator - CLI entry point.

Collects CVEs from multiple security tools and resolves fix versions from OSV API.

Usage:
  python3 unified-security-aggregator.py --severity HIGH,CRITICAL --project-dir /path/to/project
  python3 unified-security-aggregator.py --apply-fixes --project-dir /path/to/project
"""

import sys
sys.path.insert(0, '/scripts')

from security_aggregator.cli import main
sys.exit(main())