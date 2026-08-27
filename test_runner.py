#!/usr/bin/env python3
"""
Runs every payload in test_payloads.py through log_firewall.py and reports
whether the firewall's verdict matched what was expected.

Usage:
  export OPENROUTER_API_KEY="sk-or-..."
  python test_runner.py
"""

from log_firewall import check_message
from test_payloads import PAYLOADS

def run():
    results = []
    for case in PAYLOADS:
        verdict = check_message(case["content"])
        got_flag = bool(verdict.get("flagged"))
        passed = got_flag == case["expected_flag"]
        results.append({**case, "verdict": verdict, "passed": passed})

    print(f"{'ID':<28} {'Expected':<10} {'Got':<10} {'Result':<8} Reason")
    print("-" * 90)
    for r in results:
        print(
            f"{r['id']:<28} "
            f"{str(r['expected_flag']):<10} "
            f"{str(bool(r['verdict'].get('flagged'))):<10} "
            f"{'PASS' if r['passed'] else 'FAIL':<8} "
            f"{r['verdict'].get('reason', '')[:40]}"
        )

    total = len(results)
    passed_count = sum(r["passed"] for r in results)
    print("-" * 90)
    print(f"Score: {passed_count}/{total} correct ({passed_count/total*100:.0f}%)")


if __name__ == "__main__":
    run()
