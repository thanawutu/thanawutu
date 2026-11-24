#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Modular input rapid7_vuln_content:// (see r7_collect.py)."""
import sys

import r7_lib  # noqa: F401  (adds bin/lib to sys.path)
from r7_collect import VulnContentCollector

if __name__ == "__main__":
    sys.exit(VulnContentCollector().run(sys.argv))
