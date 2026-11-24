#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""... | r7vercheck ranges="8.1 < 8.1.34 ; 8.2 < 8.2.29" [field=version] [vendor_field=vendor]

Adds range_status (In range / Check advisory / Not in range / Unknown) and
in_range (1/0). Versions are compared segment by segment as numbers.
"""
from __future__ import absolute_import

import sys

import r7_lib as L
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option


@Configuration()
class R7VerCheck(StreamingCommand):
    ranges = Option(require=True)
    field = Option(require=False, default="version")
    vendor_field = Option(require=False, default="vendor")

    @L.safe
    def stream(self, records):
        L.parse_ranges(self.ranges)  # fail fast on bad input
        for r in records:
            v = r.get(self.field)
            if isinstance(v, list):
                v = v[0] if v else ""
            status = L.range_status(v, self.ranges, r.get(self.vendor_field) or "")
            r["range_status"] = status
            r["in_range"] = 1 if status in ("In range", "Check advisory") else 0
            yield r


if __name__ == "__main__":
    dispatch(R7VerCheck, sys.argv, sys.stdin, sys.stdout, __name__)
