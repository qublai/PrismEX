#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Legacy macro-related helpers.

Portable Executable analysis sometimes overlaps with document/macro workflows.
This module is not part of the default PrismEX scan, but is kept for advanced
users.

@QK
"""

import re
from oletools.olevba3 import VBA_Parser


def get_result(filename):
    """Extract basic VBA macro behavior using oletools.

    Returns an empty dict if the file is not a supported OLE/OpenXML container
    or if parsing fails.

    @QK
    """
    behavior = {}

    try:
        vbaparser = VBA_Parser(filename)
    except Exception:
        return {}

    try:
        if vbaparser.detect_vba_macros():
            results = vbaparser.analyze_macros()
            for item in results:
                details = re.sub(r"\(.*\)", "", str(item[2]))
                details = details.replace("strings", "str")
                details = re.sub(r" $", "", details)

                if item[0] in {"AutoExec", "Suspicious"}:
                    behavior.update({item[1]: details})

            macro = vbaparser.reveal()
            attributes = re.findall(r"Attribute VB.*", macro, flags=re.MULTILINE)
            macro = re.sub(r"Attribute VB.*", "", macro)

            return {"behavior": behavior, "macro": macro, "attributes": attributes}

        return {}
    except Exception:
        return {}
    finally:
        try:
            vbaparser.close()
        except Exception:
            pass
