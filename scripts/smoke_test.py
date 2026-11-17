#!/usr/bin/env python3
"""Contract / smoke tests derived from the OAS, run against each regional data plane (7.1-7.8).

Requests use the real hostname and SNI but connect to each region's address (curl --resolve),
so both regions are verified independently (T3, C17).

Secrets (environment): TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_SCOPE   -> valid token
                       WRONG_ISSUER_TOKEN, LOW_SCOPE_TOKEN              -> optional negative tests
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

from common import load_env, load_manifest, load_spec, operations, target_variants

results = []


def record(region, name, ok, detail=""):
    results.append({"region": region, "test": name, "ok": ok, "detail": detail})
    print(("PASS " if ok else "FAIL ") + f"[{region}] {name} {detail}")


def curl(host, ip, method, path, token=None, body=None):
    cmd = ["curl", "-sS", "-o", "-", "-D", "-", "--max-time", "20", "-X", method,
           "--resolve", f"{host}:443:{ip}", f"https://{host}{path}"]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    head, _, payload = out.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP") else 0
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    return status, hdrs, payload


def get_token(url):
    cid, sec = os.environ.get("TEST_CLIENT_ID"), os.environ.get("TEST_CLIENT_SECRET")
    if not (cid and sec):
        return None
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cid,
                                   "client_secret": sec, "scope": os.environ.get("TEST_SCOPE", "")}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=20) as r:
        return json.load(r)["access_token"]


def sample(schema):
    schema = schema or {}
    if "example" in schema:
        return schema["example"]
    if schema.get("enum"):
        return schema["enum"][0]
    return {"integer": 1, "number": 1, "boolean": True}.get(schema.get("type"), "1")


def concrete_path(prefix, op):
    path = op["path"]
    for p in op["parameters"]:
        if p["in"] == "path":
            ex = p.get("example", sample(p.get("schema")))
            path = path.replace("{" + p["name"] + "}", str(ex))
    return prefix + path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--config-revision", required=True)
    ap.add_argument("--branch-prefix", default="", help="e.g. /branch-<slug> for Dev branch deploys")
    ap.add_argument("--rate-limit", action="store_true")
    ap.add_argument("--out", default="smoke-results.json")
    a = ap.parse_args()

    m, env = load_manifest(a.manifest), load_env(a.target)
    spec, _ = load_spec(m["_spec_path"])
    prefix = f"{a.branch_prefix}/{m['api']}/v{m['major']}"
    variants = target_variants(a.target, m["exposure"])
    all_ops = list(operations(spec))
    token_url = env["smoke"]["token_url"]
    token = get_token(token_url)
    if not token:
        record("-", "acquire test token", False, "TEST_CLIENT_ID/SECRET not set")

    for v in variants:
        host = env["hostnames"][v]
        ops = [o for o in all_ops if not (v == "ext" and m.get("external_operations") is not None
               and o["operationId"] not in m["external_operations"])]
        hidden = [o for o in all_ops if o not in ops]
        for region in env["regions"]:
            rn, ip = f"{region['name']}/{v}", socket.gethostbyname(region["address"])
            for o in ops:
                path = concrete_path(prefix, o)
                documented = {int(c) for c in (o["op"].get("responses") or {}) if str(c).isdigit()}
                tag = f"{o['operationId']}"
                # 7.3 negative auth
                s, h, _ = curl(host, ip, o["method"], path)
                record(rn, f"{tag}: no token -> 401", s == 401, f"got {s}")
                s, _, _ = curl(host, ip, o["method"], path, token="not.a.jwt")
                record(rn, f"{tag}: invalid token -> 401", s == 401, f"got {s}")
                if os.environ.get("WRONG_ISSUER_TOKEN"):
                    s, _, _ = curl(host, ip, o["method"], path, token=os.environ["WRONG_ISSUER_TOKEN"])
                    record(rn, f"{tag}: wrong issuer -> 401", s == 401, f"got {s}")
                if os.environ.get("LOW_SCOPE_TOKEN"):
                    s, _, _ = curl(host, ip, o["method"], path, token=os.environ["LOW_SCOPE_TOKEN"])
                    record(rn, f"{tag}: insufficient scope -> 403", s == 403, f"got {s}")
                if not token:
                    continue
                # 7.2 positive (safe methods only) + headers
                if o["method"] == "GET":
                    s, h, _ = curl(host, ip, "GET", path, token=token)
                    record(rn, f"{tag}: valid token -> documented status", s in documented, f"got {s}")
                    record(rn, f"{tag}: API-Version header", h.get("api-version") == str(m["semver"]),
                           f"got {h.get('api-version')}")
                    # 7.7 configuration revision present in this region
                    record(rn, f"{tag}: config revision", h.get("x-config-revision") == a.config_revision,
                           f"got {h.get('x-config-revision')}")
                    if m["backend"]["mode"] == "mock":
                        record(rn, f"{tag}: X-Mock-Response", h.get("x-mock-response") == "true")
                # 7.4 request validation: empty body must be rejected when the contract requires fields
                body = (o["op"].get("requestBody") or {}).get("content", {}).get("application/json", {})
                if body.get("schema", {}).get("required"):
                    s, _, _ = curl(host, ip, o["method"], path, token=token, body={})
                    record(rn, f"{tag}: invalid payload -> 400", s == 400, f"got {s}")
            # 7.8 isolation: operations not exposed on this variant must not route
            for o in hidden:
                s, _, _ = curl(host, ip, o["method"], concrete_path(prefix, o), token=token)
                record(rn, f"isolation: {o['operationId']} not routable on {v} host", s == 404, f"got {s}")
            # 7.5 rate limit
            probe = int(env["smoke"].get("rate_limit_probe", 0))
            if a.rate_limit and probe and token:
                get_op = next((o for o in ops if o["method"] == "GET"), None)
                if get_op:
                    codes = [curl(host, ip, "GET", concrete_path(prefix, get_op), token=token)[0]
                             for _ in range(probe)]
                    record(rn, f"rate limit trips within {probe} requests", 429 in codes)

    ok = all(r["ok"] for r in results)
    json.dump(results, open(a.out, "w"), indent=2)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"### Smoke tests: {m['api']} v{m['major']} on {a.target}\n\n"
                     f"{sum(r['ok'] for r in results)}/{len(results)} passed\n\n")
            for r in results:
                if not r["ok"]:
                    fh.write(f"- FAIL `{r['region']}` {r['test']} {r['detail']}\n")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
