#!/usr/bin/env python3
"""Scoped-apply guard (C1, 4.13): inspect `terraform show -json <plan>` and refuse a plan
that touches anything outside this API's tagged Konnect Gateway entities.

  plan_guard.py PLAN.json --api contracts --major 1 [--summary out.md]
"""
import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("plan")
    ap.add_argument("--api", required=True)
    ap.add_argument("--major", required=True)
    ap.add_argument("--summary")
    a = ap.parse_args()
    plan = json.load(open(a.plan))
    want = {f"api:{a.api}", f"api-major:v{a.major}"}
    counts, bad = {}, []
    for rc in plan.get("resource_changes", []):
        acts = tuple(rc["change"]["actions"])
        if acts == ("no-op",):
            continue
        counts[acts] = counts.get(acts, 0) + 1
        if not rc["type"].startswith("konnect_gateway_"):
            bad.append(f"{rc['address']}: type outside konnect_gateway_*")
            continue
        for side in ("before", "after"):
            state = rc["change"].get(side)
            if state is None:
                continue
            tags = set(state.get("tags") or [])
            if not want <= tags:
                bad.append(f"{rc['address']} ({side}): not tagged {sorted(want)}")
    lines = ["No changes."]
    if counts:
        lines = ["| Action | Count |", "| --- | --- |"] + \
                [f"| {'+'.join(k)} | {v} |" for k, v in sorted(counts.items())]
    text = "\n".join(lines)
    print(text)
    if a.summary:
        open(a.summary, "w").write(text + "\n")
    for b in bad:
        print(f"::error title=plan-guard::{b}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
