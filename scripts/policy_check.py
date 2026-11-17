#!/usr/bin/env python3
"""Pipeline policy gates (Phase 5, Section 4.3). Exits non-zero on any violation.

  pre-generation : manifest / contract / environment checks
  post-generation: checks on the generated Terraform (pass --generated DIR)

  policy_check.py --manifest M --target T [--generated build] [--branch B]
                  [--prev-spec PATH --oasdiff-breaking F --oasdiff-changes F] [--rollback]
  policy_check.py --manifest M --print-hashes     # values for policy/ea-approvals.yaml
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

from common import (
    REQUIRED_TAGS, ROOT, external_spec_problems, SEMVER_RE, TARGETS, load_env, load_manifest, load_spec,
    load_yaml, oidc_requirements, operations, regex_path_to_oas, service_name,
    sha256_file, target_variants, walk_strings, branch_slug,
)
from oas2tf import has_example

IDP_ISSUER = {  # D-21a: one provider per variant, and the right one
    "int": ("entra_id", re.compile(r"^https://(login\.microsoftonline\.com|sts\.windows\.net)/[^/]+/")),
    "ext": ("entra_external_id", re.compile(r"^https://[^/]+\.ciamlogin\.com/[^/]+/")),
}
LOGGING_TELEMETRY = {"file-log", "syslog", "tcp-log", "udp-log", "opentelemetry", "prometheus"}
# openid-connect is verified per Route below, so it is not in this service/global-level set
REQUIRED_PLUGINS = {"rate-limiting", "correlation-id"}
SECRET_KEY = re.compile(r"(secret|password|passwd|api[_-]?key|private[_-]?key|credentials?)$|^(access_|refresh_|bearer_)?token$", re.I)
SECRET_OK = re.compile(r"^\{vault://[^}]+\}$|^\$\{")
PLACEHOLDER_HOSTS = re.compile(r"(\.invalid$|^localhost$|^127\.|^mock[.-]|placeholder)", re.I)


def spec_hashes(m, files):
    return {"spec_sha256": sha256_file(m["_spec_path"]),
            "schemas_sha256": hashlib.sha256(
                "".join(f"{pathlib.Path(f).name}:{sha256_file(f)}" for f in files).encode()).hexdigest()}


def pre_checks(m, spec, files, target, env, a, fail):
    api = m.get("api")
    # --- manifest sanity ---------------------------------------------------
    for k in ("api", "domain", "major", "semver", "exposure", "owner", "lifecycle", "spec", "backend"):
        if k not in m:
            fail("manifest", f"missing field '{k}'")
    if m.get("_spec_external"):
        for e in external_spec_problems(m["_spec_external"]):
            fail("manifest", e)
    if "semver" not in m or "major" not in m:
        return
    if not SEMVER_RE.match(str(m["semver"])):
        fail("manifest", f"semver '{m['semver']}' is not valid semver")
    elif int(str(m["semver"]).split(".")[0]) != int(m["major"]):
        fail("5.5", f"semver major {m['semver']} != manifest major v{m['major']}")
    if str(spec.get("info", {}).get("version")) != str(m["semver"]):
        fail("manifest", f"OAS info.version '{spec.get('info', {}).get('version')}' != manifest semver '{m['semver']}'")
    if m["exposure"] not in ("internal", "external", "both"):
        fail("manifest", f"exposure '{m['exposure']}' invalid")
    mode = (m.get("backend") or {}).get("mode")
    if mode not in ("mock", "live", "mixed"):
        fail("manifest", f"backend.mode '{mode}' invalid")
    if a.branch and target != "dev":
        fail("D-18", "branch deployments are Dev-only")

    # --- 5.7 target matches approved exposure (D-20a) ---------------------------
    variants = target_variants(target, m["exposure"])
    if not variants:
        fail("5.7", f"target {target} is not allowed for exposure '{m['exposure']}'")

    # --- 5.8 no mocks in production (D-03) ---------------------------------------
    if target.startswith("prod"):
        if mode in ("mock", "mixed"):
            fail("5.8", f"backend.mode '{mode}' is not allowed on {target}")
        up = ((m.get("targets") or {}).get(target) or {}).get("upstream") or {}
        if PLACEHOLDER_HOSTS.search(str(up.get("host", ""))):
            fail("5.8", f"placeholder upstream host '{up.get('host')}' on {target}")

    # --- contract completeness (0.3, 0.4) ---------------------------------------
    ops = list(operations(spec))
    ids = [o["operationId"] for o in ops]
    for o in ops:
        if not o["operationId"]:
            fail("5.5", f"{o['method']} {o['path']} has no operationId (needed for Route names)")
    for dup in {i for i in ids if i and ids.count(i) > 1}:
        fail("5.5", f"duplicate operationId '{dup}'")
    for o in ops:
        scopes, usable, alts = oidc_requirements(spec, o["security"])
        if not usable:
            fail("5.2", f"{o['operationId']}: no OAuth2/OIDC/bearer security requirement; "
                        "every operation (mocks included) must be protected by OIDC")
    if mode in ("mock", "mixed"):
        if not str(spec.get("openapi", "")).startswith("3.0") and not spec.get("swagger"):
            fail("0.4", f"OAS {spec.get('openapi')} is not supported by the Mocking plugin (3.0/2.0 only)")
        mocked = {o["operationId"] for o in ops} if mode == "mock" else set(m["backend"].get("mock_operations") or [])
        for o in ops:
            if o["operationId"] in mocked and not has_example(o):
                fail("0.4", f"{o['operationId']}: no 2xx response example, required for mocking")
    ext_ops = m.get("external_operations")
    if ext_ops is not None:
        for i in set(ext_ops) - set(ids):
            fail("5.5", f"external_operations lists unknown operationId '{i}'")

    # --- per-target parameters present ------------------------------------------------
    tgt = (m.get("targets") or {}).get(target)
    if tgt is None:
        fail("4.11", f"manifest.targets.{target} missing (upstream/audience are target-specific)")
    else:
        for v in variants:
            if not (tgt.get("audience") or {}).get(v):
                fail("4.11", f"targets.{target}.audience.{v} missing")
        if mode != "mock" and not (tgt.get("upstream") or {}).get("host"):
            fail("4.11", f"targets.{target}.upstream.host missing")

    # --- 5.6 exactly one correct IdP per variant (D-21a) --------------------------------
    ident = env.get("identity") or {}
    for v in variants:
        cfg = ident.get(v)
        if not isinstance(cfg, dict):
            fail("5.6", f"{target}: no identity provider configured for variant '{v}'")
            continue
        want_type, pat = IDP_ISSUER[v]
        if cfg.get("type") != want_type or not pat.match(str(cfg.get("issuer", ""))):
            fail("5.6", f"{target}/{v}: issuer must be {want_type} (got {cfg.get('type')} {cfg.get('issuer')})")
    if "int" in variants and "ext" in variants and \
            (ident.get("int") or {}).get("issuer") == (ident.get("ext") or {}).get("issuer"):
        fail("5.6", "internal and external variants share one issuer")

    # --- 5.9 path / hostname conflicts (Layer 4) -----------------------------------------
    reg = load_yaml(ROOT / "policy" / "ownership-registry.yaml").get("apis") or []
    mine = f"/{api}/v{m['major']}"
    entry = next((r for r in reg if r["api"] == api and int(r["major"]) == int(m["major"])), None)
    if not entry:
        fail("5.9", f"{api} v{m['major']} is not in policy/ownership-registry.yaml")
    else:
        if entry["owner"] != m.get("owner"):
            fail("5.9", f"manifest owner '{m.get('owner')}' != registry owner '{entry['owner']}'")
        if entry["path_prefix"] != mine:
            fail("5.9", f"registry path_prefix '{entry['path_prefix']}' != '{mine}'")
    for r in reg:
        if (r["api"], int(r["major"])) == (api, int(m["major"])):
            continue
        p = r["path_prefix"].rstrip("/") + "/"
        if (mine + "/").startswith(p) or p.startswith(mine + "/"):
            fail("5.9", f"path prefix {mine} overlaps {r['path_prefix']} owned by {r['owner']}")
    hosts = [h for h in (env.get("hostnames") or {}).values() if h]
    if len(hosts) != len(set(hosts)):
        fail("5.9", "internal and external hostnames must differ")

    # --- 5.10 EA approval for the exact revision (C19, D-24) ---------------------------------
    h = spec_hashes(m, files)
    approvals = (load_yaml(ROOT / "policy" / "ea-approvals.yaml") or {}).get("approvals") or []
    ok = any(x.get("api") == api and int(x.get("major", -1)) == int(m["major"]) and
             x.get("spec_sha256") == h["spec_sha256"] and x.get("schemas_sha256") == h["schemas_sha256"]
             for x in approvals)
    if not ok:
        fail("5.10", "no EA approval matches this exact spec + schema revision "
                     f"(spec {h['spec_sha256'][:12]}, schemas {h['schemas_sha256'][:12]}); missing or stale")

    # --- 5.11 change classification (C6, Section 6) ------------------------------------------
    if a.rollback:
        print("note: --rollback set; change classification skipped (restoring approved state)")
    elif a.prev_spec and pathlib.Path(a.prev_spec).exists():
        prev = load_spec(a.prev_spec)[0]
        pv, nv = str(prev.get("info", {}).get("version")), str(m["semver"])
        breaking = _load_list(a.oasdiff_breaking)
        changes = _load_list(a.oasdiff_changes)
        comp = m.get("compatibility") or {}
        if changes and pv == nv:
            fail("5.11", f"contract changed ({len(changes)} diffs) but semver is still {nv}")
        if changes and pv != nv:
            if not (comp.get("determined_by") and comp.get("determination") in ("compatible", "breaking")):
                fail("5.11", "contract differs from last prod-deployed revision; manifest.compatibility "
                             "(determined_by, determination, date) must record the team's determination")
            same_major = pv.split(".")[0] == nv.split(".")[0]
            if breaking and same_major and not nv.split("-")[0].startswith("0."):
                fail("5.11", f"{len(breaking)} breaking change(s) detected but major is unchanged "
                             f"({pv} -> {nv}); breaking changes require a new major (D-07)")
            if comp.get("determination") == "breaking" and same_major:
                fail("5.11", "team determined the change is breaking but the major version is unchanged")
            if comp.get("determination") == "compatible" and breaking:
                fail("5.11", "team recorded 'compatible' but oasdiff reports breaking changes; resolve before promotion")
    elif target.startswith("prod"):
        print("note: no previous prod-deployed contract found; treated as first deployment (Section 6.2 review applies)")


def _load_list(p):
    if not p or not pathlib.Path(p).exists():
        return []
    txt = pathlib.Path(p).read_text().strip()
    if not txt:
        return []
    try:
        data = json.loads(txt)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def post_checks(m, spec, target, env, a, fail):
    allow = set((load_yaml(ROOT / "policy" / "plugin-allowlist.yaml") or {}).get("plugins") or [])
    glob = set(env.get("global_plugins") or [])
    for g in glob - allow:
        fail("5.3", f"{target}: global plugin '{g}' is not on the allow-list")
    slug = branch_slug(a.branch) if a.branch else None
    expected = {tuple(sorted((o["method"], o["path"]) for o in operations(spec)))}
    for v in target_variants(target, m["exposure"]):
        d = pathlib.Path(a.generated) / target / (f"{v}-b-{slug}" if slug else v)
        f = d / "main.tf.json"
        if not f.exists():
            fail("gen", f"{f} not generated")
            continue
        doc = json.loads(f.read_text())
        res = doc["resource"]
        svc_name = service_name(m, v, slug)
        ctx = f"{target}/{v}"

        # 5.1 naming + tags
        svcs = res.get("konnect_gateway_service", {})
        if len(svcs) != 1 or next(iter(svcs.values()))["name"] != svc_name:
            fail("5.1", f"{ctx}: expected exactly one Service named '{svc_name}'")
        want_tags = {
            "api": m["api"], "api-major": f"v{m['major']}", "api-version": str(m["semver"]),
            "exposure": "internal" if v == "int" else "external", "owner": m["owner"],
            "lifecycle": m["lifecycle"], "env": target, "backend": m["backend"]["mode"]}
        for rtype, items in res.items():
            for label, body in items.items():
                tags = dict(t.split(":", 1) for t in body.get("tags", []) if ":" in t)
                for k in REQUIRED_TAGS:
                    if tags.get(k) != want_tags[k]:
                        fail("5.1", f"{ctx}: {rtype}.{label} tag {k}={tags.get(k)!r}, expected {want_tags[k]!r}")
                if "config-revision" not in tags:
                    fail("5.1", f"{ctx}: {rtype}.{label} missing config-revision tag (4.16)")
                if rtype == "konnect_gateway_route" and not re.fullmatch(
                        re.escape(svc_name) + r"-[A-Za-z0-9_]+", body["name"]):
                    fail("5.1", f"{ctx}: Route name '{body['name']}' not '{{service}}-{{operationId}}'")

        # plugin inventory (5.2, 5.3)
        by_route, svc_plugins, all_names = {}, set(), set()
        for rtype, items in res.items():
            if not rtype.startswith("konnect_gateway_plugin_"):
                continue
            name = rtype[len("konnect_gateway_plugin_"):].replace("_", "-")
            all_names.add(name)
            for label, body in items.items():
                if "route" in body:
                    by_route.setdefault(body["route"]["id"], set()).add(name)
                elif "service" in body:
                    svc_plugins.add(name)
        for n in all_names - allow:
            fail("5.3", f"{ctx}: plugin '{n}' is not on the allow-list")
        effective = svc_plugins | glob
        for n in REQUIRED_PLUGINS - effective:
            fail("5.2", f"{ctx}: required plugin '{n}' missing (not at service level or global)")
        if not (effective & LOGGING_TELEMETRY):
            fail("5.2", f"{ctx}: no logging/telemetry plugin (service-level or global)")
        for rlabel, rbody in res.get("konnect_gateway_route", {}).items():
            rid = f"${{konnect_gateway_route.{rlabel}.id}}"
            if "openid-connect" not in by_route.get(rid, set()):
                fail("5.2", f"{ctx}: Route {rbody['name']} has no per-Route openid-connect plugin")
            idp = [b for b in res.get("konnect_gateway_plugin_openid_connect", {}).values()
                   if b.get("route", {}).get("id") == rid]
            for b in idp:  # 5.6 on generated output
                if not IDP_ISSUER[v][1].match(str(b["config"].get("issuer", ""))):
                    fail("5.6", f"{ctx}: {rbody['name']} issuer {b['config'].get('issuer')} wrong for variant")
                if not b["config"].get("audience_required"):
                    fail("5.2", f"{ctx}: {rbody['name']} has no audience check")
        if target.startswith("prod") and ("mocking" in all_names or any(
                PLACEHOLDER_HOSTS.search(s["host"]) for s in svcs.values())):
            fail("5.8", f"{ctx}: mock configuration present in generated production config")

        # 5.4 plaintext secrets
        for path, val in walk_strings(res):
            key = next((p for p in reversed(path) if not p.isdigit()), "")
            if SECRET_KEY.search(key) and val and not SECRET_OK.match(val) \
                    and "api_specification" not in path:
                fail("5.4", f"{ctx}: possible plaintext secret at {'.'.join(path)}; use a {{vault://...}} reference")

        # 5.5 routes match the contract
        prefix = f"/branch-{slug}/{m['api']}/v{m['major']}" if slug else f"/{m['api']}/v{m['major']}"
        got = []
        for rbody in res.get("konnect_gateway_route", {}).values():
            for p in rbody["paths"]:
                oas = regex_path_to_oas(prefix, p)
                if oas is None:
                    fail("5.5", f"{ctx}: Route {rbody['name']} path '{p}' is outside {prefix}")
                    continue
                got.append((rbody["methods"][0], oas))
        want_ops = [(o["method"], o["path"]) for o in operations(spec)
                    if not (v == "ext" and m.get("external_operations") is not None
                            and o["operationId"] not in m["external_operations"])]
        for x in set(want_ops) - set(got):
            fail("5.5", f"{ctx}: contract operation {x[0]} {x[1]} has no Route")
        for x in set(got) - set(want_ops):
            fail("5.5", f"{ctx}: Route {x[0]} {x[1]} is not in the contract")
        if len(got) != len(set(got)):
            fail("5.5", f"{ctx}: duplicate Routes")
        major_in_path = re.search(r"/v(\d+)(/|$)", prefix)
        if not major_in_path or int(major_in_path.group(1)) != int(m["major"]):
            fail("5.5", f"{ctx}: path major version does not match contract major v{m['major']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--target", choices=TARGETS)
    ap.add_argument("--generated")
    ap.add_argument("--branch")
    ap.add_argument("--prev-spec")
    ap.add_argument("--oasdiff-breaking")
    ap.add_argument("--oasdiff-changes")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--print-hashes", action="store_true")
    a = ap.parse_args()

    m = load_manifest(a.manifest)
    spec, files = load_spec(m["_spec_path"])
    if a.print_hashes:
        h = spec_hashes(m, files)
        print(f"- api: {m['api']}\n  major: {m['major']}\n  spec_sha256: {h['spec_sha256']}\n"
              f"  schemas_sha256: {h['schemas_sha256']}\n  approved_by: <EA reviewer>\n  ticket: <ref>")
        return
    if not a.target:
        sys.exit("--target is required")
    env = load_env(a.target)
    problems = []
    fail = lambda rule, msg: problems.append((rule, msg))
    pre_checks(m, spec, files, a.target, env, a, fail)
    if a.generated and not problems:
        post_checks(m, spec, a.target, env, a, fail)
    for rule, msg in problems:
        print(f"::error title=policy {rule}::{m['api']} v{m['major']} -> {a.target}: {msg}")
    print(f"policy: {len(problems)} violation(s) for {m['api']} v{m['major']} -> {a.target}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
