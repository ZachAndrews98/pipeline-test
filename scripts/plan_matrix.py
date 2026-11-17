#!/usr/bin/env python3
"""Decide which manifests deploy to which targets. Writes GitHub outputs.

  plan_matrix.py --changed-files FILE [--manifest NAME|all]
Platform-level changes (environments/, policy/, scripts/) select every manifest;
otherwise only manifests whose own file or spec directory changed.
"""
import argparse
import json
import os
import pathlib

from common import ROOT, load_manifest, targets_for_exposure

PLATFORM_DIRS = ("environments/", "policy/", "scripts/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--changed-files")
    ap.add_argument("--manifest", default="")
    a = ap.parse_args()

    manifests = sorted((ROOT / "manifests").glob("*.yaml"))
    changed = []
    if a.changed_files and pathlib.Path(a.changed_files).exists():
        changed = [l.strip() for l in open(a.changed_files) if l.strip()]
    run_all = a.manifest == "all" or any(c.startswith(PLATFORM_DIRS) for c in changed)

    selected = []
    for p in manifests:
        m = load_manifest(p, fetch=False)
        rel_m = f"manifests/{p.name}"
        # External specs are pinned by ref in the manifest, so a bump shows up as a manifest change.
        spec_dir = None if m["_spec_external"] else str(m["_spec_path"].parent.relative_to(ROOT)) + "/"
        if a.manifest and a.manifest != "all":
            hit = p.stem == a.manifest or p.name == a.manifest
        else:
            hit = run_all or rel_m in changed or (spec_dir and any(c.startswith(spec_dir) for c in changed))
        if hit:
            selected.append((p.stem, m))

    out = {"manifests": [n for n, _ in selected]}
    for t in ("dev", "uat", "prod-internal", "prod-external"):
        out[t.replace("-", "_")] = [n for n, m in selected
                                    if t in targets_for_exposure(m["exposure"], m["backend"]["mode"])]
    for k, v in out.items():
        line = f"{k}={json.dumps(v)}"
        print(line)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
                fh.write(line + "\n")


if __name__ == "__main__":
    main()
