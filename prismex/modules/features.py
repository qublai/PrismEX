#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Legacy feature extraction helpers.

Not all modules are used by the current PrismEX engine, but they are retained
for users who want to build custom pipelines.

@QK
"""

import os
import json

import array

from . import apialert
from . import yara_check


def xor_delta(s, key_len=1):
    delta = array.array("B", s)

    for x in range(key_len, len(s)):
        delta[x - key_len] ^= delta[x]

    """ return the delta as a string """
    return delta.tostring()[:-key_len]


def get_xor(filename, search_string=False):
    xorsearch_custom = False
    check = {}
    offset_list = []
    search_file = open(filename, "rb").read()
    key_lengths = [1, 2, 4, 8]
    if not search_string:
        search_string = b"This program cannot be run in DOS mode."
    else:
        str(search_string)
        xorsearch_custom = True
    is_xored = False

    for key_len in key_lengths:
        key_delta = xor_delta(search_string, key_len)
        doc_delta = xor_delta(search_file, key_len)

        offset = -1
        while True:
            offset += 1
            offset = doc_delta.find(key_delta, offset)

            if (offset > 0) and offset not in offset_list:
                offset_list.append(offset)
                f = open(filename, "rb")
                f.seek(offset, 0)
                data = f.read(39)
                if search_string not in data:
                    is_xored = True

                try:
                    data = str(data.decode("utf-8"))
                except Exception:
                    data = str(data)

                check.update({hex(offset): data})
            else:
                break

    if is_xored or xorsearch_custom:
        return check
    else:
        return {}


def get_antivm(filename):
    result = {}

    # Credit: Joxean Koret
    VM_Sign = {
        "VMware trick": b"VMXh",
        "Xen": b"XenVMM",
        "Red Pill": b"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick": b"\x0f\x3f\x07\x0b",
        "VMCheck.dll": b"\x45\xc7\x00\x01",
        "VMCheck.dll for VirtualPC": b"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Bochs & QEmu CPUID Trick": b"\x44\x4d\x41\x63",
        "Torpig VMM Trick": b"\xe8\xed\xff\xff\xff\x25\x00\x00\x00\xff\x33\xc9\x3d\x00\x00\x00\x80\x0f\x95\xc1\x8b\xc1\xc3",
        "Torpig (UPX) VMM Trick": b"\x51\x51\x0f\x01\x27\x00\xc1\xfb\xb5\xd5\x35\x02\xe2\xc3\xd1\x66\x25\x32\xbd\x83\x7f\xb7\x4e\x3d\x06\x80\x0f\x95\xc1\x8b\xc1\xc3",
    }

    with open(filename, "rb") as f:
        buf = f.read()

        for trick in VM_Sign:
            pos = buf.find(VM_Sign[trick])
            if pos > -1:
                result.update({"trick": trick, "offset": hex(pos)})

    return result


def path_to_file(filename, folder):
    _ROOT = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(_ROOT, folder, filename)


def load_config(config_file):
    with open(config_file) as conf:
        data = json.load(conf)
    return data


def get_result(pe, filename):
    features = {}
    features.update(
        {
            "mutex": apialert.get_result(
                pe, load_config(path_to_file("stringsmatch.json", "../signatures"))["mutex"]
            ),
            "antidbg": apialert.get_result(
                pe, load_config(path_to_file("stringsmatch.json", "../signatures"))["antidbg"]
            ),
            "antivm": get_antivm(filename),
            "xor": get_xor(filename),
            "packer": yara_check.yara_match_from_file(
                path_to_file("peid.yara", "../signatures/yara_plugins/pe"), filename
            ),
            "crypto": yara_check.yara_match_from_file(
                path_to_file("crypto_signatures.yar", "../signatures/yara_plugins/pe"), filename
            ),
        }
    )
    return features
