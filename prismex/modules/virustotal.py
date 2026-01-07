#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""VirusTotal integration stubs (offline by default).

PrismEX is designed to work fully offline. This module is kept as a placeholder
for future enrichment workflows where an operator might query VirusTotal
separately.

@QK
"""

from virus_total_apis import PublicApi as VirusTotalPublicApi


def get_result(API_KEY, HASH, full=False):
    vt = VirusTotalPublicApi(API_KEY)
    response = vt.get_file_report(HASH)
    if full:
        return response
    try:
        return {"positives": response["results"]["positives"], "total": response["results"]["total"]}
    except Exception:
        return {"positives": "", "total": ""}
