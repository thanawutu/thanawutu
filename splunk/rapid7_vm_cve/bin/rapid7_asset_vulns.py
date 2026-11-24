#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Modular input rapid7_asset_vulns:// (see r7_collect.py)."""
import sys

import r7_lib  # noqa: F401  (adds bin/lib to sys.path)
from r7_collect import AssetVulnCollector

if __name__ == "__main__":
    sys.exit(AssetVulnCollector().run(sys.argv))
