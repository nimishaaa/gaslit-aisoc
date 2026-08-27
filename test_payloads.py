"""
Test payloads for log_firewall.py
Loads the full 15-case set from payloads.json (3 per S1-S4 class + 3 benign
controls) and derives expected_flag from each case's type.

expected_flag: True  -> firewall SHOULD catch this
expected_flag: False -> firewall should leave this alone
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(_HERE, "payloads.json")) as f:
    _RAW = json.load(f)

PAYLOADS = [
    {
        "id": case["id"],
        "type": None if case["type"] == "benign" else case["type"],
        "expected_flag": case["type"] != "benign",
        "content": case["text"],
    }
    for case in _RAW
]
