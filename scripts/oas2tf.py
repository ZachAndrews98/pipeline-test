#!/usr/bin/env python3
"""Convert an OAS contract + deployment manifest into Konnect Terraform JSON.

One Terraform root is emitted per (target, variant) so every apply is scoped
to a single API variant with its own state (C1). Only target-specific values
(upstream, issuer, audience, hostnames, limits) vary between targets (C4).

  oas2tf.py --manifest manifests/x.yaml --target dev --out build \
            --config-revision <git-sha> [--branch feature/foo]
"""
import argparse
import copy
import json
import re
import sys

from common import (
    Deref, branch_slug, dump_json, load_env, load_manifest, load_spec,
    oidc_requirements, operations, route_regex_path, service_name,
    target_variants, tf_label,
)

PLACEHOLDER_UPSTREAM = {"protocol": "http", "host": "mock.invalid", "port": 80, "path": None}
REF_RE = re.compile(r"^\$\{konnect_[a-z_]+\.[A-Za-z0-9_]+\.id\}$")


def tf_escape(node):
    """Stop Terraform from interpolating `${` / `%{` inside generated strings."""
    if isinstance(node, dict):
        return {k: tf_escape(v) for k, v in node.items()}
    if isinstance(node, list):
        return [tf_escape(v) for v in node]
    if isinstance(node, str) and not REF_RE.match(node):
        return node.replace("${", "$${").replace("%{", "%%{")
    return node


def has_example(op):
    for code, resp in (op["op"].get("responses") or {}).items():
        if not str(code).startswith("2"):
            continue
        for media in (resp.get("content") or {}).values():
            if "example" in media or "examples" in media or "example" in (media.get("schema") or {}):
                return True
    return False


class Builder:
    def __init__(self, manifest, target, variant, env, spec, revision, branch):
        self.m, self.target, self.variant, self.env = manifest, target, variant, env
        self.spec, self.revision = spec, revision
        self.slug = branch_slug(branch) if branch else None
        self.branch = branch
        self.res = {}
        self.cp = "${var.control_plane_id}"
        tgt = (manifest.get("targets") or {}).get(target) or {}
        self.tgt = tgt
        mode = manifest["backend"]["mode"]
        self.mode = mode
        self.mocked_ops = set(manifest["backend"].get("mock_operations") or [])
        self.svc_name = service_name(manifest, variant, self.slug)
        pre = f"/{manifest['api']}/v{manifest['major']}"
        self.prefix = f"/branch-{self.slug}{pre}" if self.slug else pre

    # ---- helpers -------------------------------------------------------
    def tags(self):
        m = self.m
        t = [
            f"api:{m['api']}", f"api-major:v{m['major']}", f"api-version:{m['semver']}",
            f"exposure:{'internal' if self.variant == 'int' else 'external'}",
            f"owner:{m['owner']}", f"lifecycle:{m['lifecycle']}", f"env:{self.target}",
            f"backend:{self.mode}", f"config-revision:{self.revision}",
            "managed-by:oas-pipeline",
        ]
        if self.branch:
            t.append(f"branch:{self.slug}")
        return t

    def add(self, rtype, label, body):
        body = {"control_plane_id": self.cp, **body}
        self.res.setdefault(rtype, {})[label] = body
        return f"${{{rtype}.{label}.id}}"

    def plugin(self, name, label, config, scope):
        rtype = "konnect_gateway_plugin_" + name.replace("-", "_")
        body = {"config": config, "enabled": True, "tags": self.tags()}
        body.update(scope)
        return self.add(rtype, label, body)

    def is_mocked(self, op_id):
        return self.mode == "mock" or (self.mode == "mixed" and op_id in self.mocked_ops)

    # ---- build ---------------------------------------------------------
    def selected_ops(self):
        ops = list(operations(self.spec))
        if self.variant == "ext" and self.m.get("external_operations") is not None:
            allowed = set(self.m["external_operations"])
            ops = [o for o in ops if o["operationId"] in allowed]
        return ops

    def mock_spec(self):
        s = copy.deepcopy(self.spec)
        s.pop("servers", None)
        s["paths"] = {self.prefix + p: item for p, item in s["paths"].items()}
        return json.dumps(s, sort_keys=True)

    def build(self):
        m, env = self.m, self.env
        ident = (env.get("identity") or {}).get(self.variant) or {}
        audience = ((self.tgt.get("audience") or {}).get(self.variant))
        up = self.tgt.get("upstream") or {}
        if self.mode == "mock":
            up = dict(PLACEHOLDER_UPSTREAM)  # Mocking plugin ends the request before the upstream
        svc_body = {
            "name": self.svc_name,
            "protocol": up.get("protocol", "https"),
            "host": up["host"], "port": up.get("port", 443),
            "tags": self.tags(),
            "connect_timeout": up.get("connect_timeout", 5000),
            "read_timeout": up.get("read_timeout", 30000),
            "write_timeout": up.get("write_timeout", 30000),
            "retries": up.get("retries", 2),
        }
        if up.get("protocol", "https") == "https":
            svc_body["tls_verify"] = up.get("tls_verify", True)
        # Backend path is applied by the Route's request-transformer (see below).
        backend_path = up.get("path") or ""
        svc = self.add("konnect_gateway_service", "svc", svc_body)
        host = (env.get("hostnames") or {}).get(self.variant)

        # Service-scoped baseline + version headers (4.9, 4.10)
        self.plugin("correlation-id", "correlation_id", {
            "header_name": (env.get("correlation_id") or {}).get("header_name", "X-Correlation-ID"),
            "generator": "uuid", "echo_downstream": True}, {"service": {"id": svc}})
        rl = dict(env.get("rate_limit") or {"minute": 600, "policy": "local"})
        rl.update((self.tgt.get("rate_limit") or {}).get(self.variant, {}))
        self.plugin("rate-limiting", "rate_limiting", rl, {"service": {"id": svc}})
        otel = (env.get("logging") or {}).get("otel_traces_endpoint")
        if otel:
            self.plugin("opentelemetry", "opentelemetry", {"traces_endpoint": otel,
                        "resource_attributes": {"service.name": self.svc_name}}, {"service": {"id": svc}})
        # Request validation against the (dereferenced, gateway-prefixed) OAS contract (4.5)
        self.plugin("oas-validation", "oas_validation", {
            "api_spec": self.mock_spec(), "api_spec_encoded": False,
            "validate_request_body": True, "validate_request_header_params": True,
            "validate_request_query_params": True, "validate_request_uri_params": True,
            "verbose_response": True}, {"service": {"id": svc}})
        headers = [f"API-Version:{m['semver']}", f"X-Config-Revision:{self.revision}"]
        if self.mode == "mock":
            headers.append("X-Mock-Response:true")
            self.plugin("response-transformer", "resp_headers",
                        {"add": {"headers": headers}}, {"service": {"id": svc}})
            self.plugin("mocking", "mocking", {"api_specification": self.mock_spec(),
                        "random_delay": False}, {"service": {"id": svc}})
        else:
            self.plugin("response-transformer", "resp_headers",
                        {"add": {"headers": headers}}, {"service": {"id": svc}})

        # One Route per operation (D-09 default) with per-Route plugins (4.5, 4.7, 4.8)
        for op in self.selected_ops():
            oid = op["operationId"]
            label = tf_label(oid)
            route_body = {
                "name": f"{self.svc_name}-{oid}",
                "protocols": ["https"],
                "methods": [op["method"]],
                "paths": [route_regex_path(self.prefix, op["path"])],
                "strip_path": False,  # prefix removal is done by request-transformer
                "preserve_host": False,
                "service": {"id": svc}, "tags": self.tags(),
            }
            if host:
                route_body["hosts"] = [host]
            route = self.add("konnect_gateway_route", f"r_{label}", route_body)
            scope = {"route": {"id": route}}

            scopes, _, _ = oidc_requirements(self.spec, op["security"])
            oidc = {
                "issuer": ident.get("issuer"), "auth_methods": ["bearer"],
                "bearer_token_param_type": ["header"],
                "verify_signature": True, "verify_claims": True,
                "audience_required": [audience] if audience else [],
                "audience_claim": ["aud"],
            }
            if scopes:
                oidc.update({"scopes_required": scopes, "scopes_claim": ["scp"]})
            roles = op["op"].get("x-required-roles")
            if roles:
                oidc.update({"roles_required": roles, "roles_claim": ["roles"]})
            self.plugin("openid-connect", f"oidc_{label}", oidc, scope)

            if self.mode == "mixed" and self.is_mocked(oid):
                self.plugin("response-transformer", f"resp_headers_{label}", {"add": {"headers":
                            headers + ["X-Mock-Response:true"]}}, scope)
                self.plugin("mocking", f"mock_{label}", {"api_specification": self.mock_spec()}, scope)
            elif self.mode != "mock":
                self.plugin("request-transformer", f"rewrite_{label}", {
                    "replace": {"uri": f"{backend_path}$(uri_captures.rest)"}}, scope)

        return self.document()

    def document(self):
        doc = {
            "terraform": {
                "required_version": ">= 1.9",
                "required_providers": {"konnect": {"source": "kong/konnect", "version": "~> 3.19"}},
                # Partial config: the workflow supplies storage account/container/key.
                "backend": {"azurerm": {}},
            },
            # Auth comes from KONNECT_SPAT in the environment; never in code.
            "provider": {"konnect": {"server_url": self.env["konnect"]["server_url"]}},
            "variable": {"control_plane_id": {"type": "string", "description": "Target control plane ID"}},
            "resource": self.res,
            "output": {
                "service_name": {"value": self.svc_name},
                "config_revision": {"value": self.revision},
                "route_count": {"value": len(self.res.get("konnect_gateway_route", {}))},
            },
        }
        return tf_escape(doc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", default="build")
    ap.add_argument("--config-revision", required=True)
    ap.add_argument("--branch")
    a = ap.parse_args()

    m = load_manifest(a.manifest)
    env = load_env(a.target)
    spec, _ = load_spec(m["_spec_path"])
    variants = target_variants(a.target, m["exposure"])
    if not variants:
        sys.exit(f"{m['api']}: exposure '{m['exposure']}' has no variant on {a.target}")
    if a.branch and a.target != "dev":
        sys.exit("branch deployments are Dev-only (D-18)")
    for v in variants:
        doc = Builder(m, a.target, v, env, spec, a.config_revision, a.branch).build()
        base = f"{a.out}/{a.target}/{v}" + (f"-b-{branch_slug(a.branch)}" if a.branch else "")
        dump_json(f"{base}/main.tf.json", doc)
        dump_json(f"{base}/meta.json", {
            "api": m["api"], "major": m["major"], "semver": m["semver"], "variant": v,
            "target": a.target, "config_revision": a.config_revision,
            "state_key": f"{m['api']}-v{m['major']}/{a.target}/{v}" +
                         (f"-b-{branch_slug(a.branch)}" if a.branch else "") + ".tfstate"})
        print(f"generated {base}/main.tf.json "
              f"({len(doc['resource'].get('konnect_gateway_route', {}))} routes)")


if __name__ == "__main__":
    main()
