"""Shared helpers for the OAS-to-Konnect pipeline scripts."""
import hashlib
import json
import pathlib
import os
import re
import subprocess
import base64

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent  # repo root
TARGETS = ("dev", "uat", "prod-internal", "prod-external")
HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$"
)
REQUIRED_TAGS = (
    "api", "api-major", "api-version", "exposure", "owner",
    "lifecycle", "env", "backend",
)


def load_yaml(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


EXTERNAL_DIR = ROOT / ".external-specs"
PINNED_REF_RE = re.compile(r"^([0-9a-f]{40}|v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*)$")


def external_spec_problems(spec):
    """Validation errors for a `spec:` mapping that points at another repository."""
    errs = []
    if not isinstance(spec.get("repo"), str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", spec["repo"]):
        errs.append("spec.repo must be 'owner/name'")
    ref = spec.get("ref")
    if not isinstance(ref, str) or not PINNED_REF_RE.match(ref):
        errs.append("spec.ref must be a full commit SHA or a semver release tag (branches are mutable)")
    path = spec.get("path")
    if not isinstance(path, str) or os.path.isabs(path) or ".." in pathlib.PurePosixPath(path).parts:
        errs.append("spec.path must be a relative path inside the spec repository")
    return errs


def _external_dest(spec):
    return EXTERNAL_DIR / (spec["repo"].replace("/", "__") + "@" + re.sub(r"[^\w.-]", "_", spec["ref"]))


def fetch_external_spec(spec):
    """Check out spec['repo'] at spec['ref'] (cached) and return the path of spec['path'].

    Private repositories authenticate with the SPEC_REPO_TOKEN environment variable."""
    errs = external_spec_problems(spec)
    if errs:
        raise ValueError("; ".join(errs))
    dest = _external_dest(spec)
    if not (dest / ".git").exists():
        host = spec.get("host", "github.com")
        auth = []
        token = os.environ.get("SPEC_REPO_TOKEN")
        if token:
            cred = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            auth = ["-c", f"http.extraheader=Authorization: Basic {cred}"]
        dest.mkdir(parents=True, exist_ok=True)
        run = lambda *a: subprocess.run(["git", *a], cwd=dest, check=True,
                                        stdout=subprocess.DEVNULL, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        run("init", "-q")
        run("remote", "add", "origin", f"https://{host}/{spec['repo']}.git")
        run(*auth, "fetch", "-q", "--depth", "1", "origin", spec["ref"])
        run("-c", "advice.detachedHead=false", "checkout", "-q", "--detach", "FETCH_HEAD")
    resolved = (dest / spec["path"]).resolve()
    if dest.resolve() not in resolved.parents:
        raise ValueError("spec.path escapes the spec repository")
    return resolved


def load_manifest(path, fetch=True):
    """Load a manifest. `spec` is a path relative to the manifest, or a mapping
    {repo, ref, path[, host]} for an OAS file kept in a different repository.
    fetch=False skips cloning the external repo (_spec_path is then the would-be location)."""
    path = pathlib.Path(path).resolve()
    m = load_yaml(path)
    m["_path"] = path
    spec = m.get("spec")
    if isinstance(spec, dict):
        m["_spec_external"] = spec
        if fetch:
            m["_spec_path"] = fetch_external_spec(spec)
        else:
            m["_spec_path"] = (_external_dest(spec) / spec.get("path", "")).resolve()
    else:
        m["_spec_external"] = None
        m["_spec_path"] = (path.parent / spec).resolve() if spec else None
    return m


def load_env(target):
    return load_yaml(ROOT / "environments" / f"{target}.yaml")


def target_variants(target, exposure):
    """Variants (int/ext) of an API that belong on a target (Section 3.2)."""
    has_int = exposure in ("internal", "both")
    has_ext = exposure in ("external", "both")
    if target in ("dev", "uat"):
        return [v for v, ok in (("int", has_int), ("ext", has_ext)) if ok]
    if target == "prod-internal":
        return ["int"] if has_int else []
    if target == "prod-external":
        return ["ext"] if has_ext else []
    raise ValueError(f"unknown target {target}")


def targets_for_exposure(exposure, backend_mode="live"):
    out = ["dev", "uat"]
    if backend_mode == "live":  # D-03: mocks never reach prod
        if exposure in ("internal", "both"):
            out.append("prod-internal")
        if exposure in ("external", "both"):
            out.append("prod-external")
    return out


def service_name(manifest, variant, branch_slug=None):
    base = f"{manifest['domain']}-{manifest['api']}-v{manifest['major']}-{variant}"
    return f"{base}-b-{branch_slug}" if branch_slug else base


def branch_slug(branch):
    """Deterministic URL-safe slug; hash suffix prevents collisions (D-18)."""
    clean = re.sub(r"[^a-z0-9]+", "-", branch.lower()).strip("-")[:20].strip("-")
    digest = hashlib.sha1(branch.encode()).hexdigest()[:6]
    return f"{clean}-{digest}" if clean else digest


def tf_label(text):
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


# --------------------------------------------------------------------------
# Full $ref dereferencing (local and relative-file refs)
# --------------------------------------------------------------------------
class Deref:
    MAX_DEPTH = 12

    def __init__(self, root_path):
        self.root = pathlib.Path(root_path).resolve()
        self.cache = {}
        self.files = {self.root}

    def load(self, path):
        path = pathlib.Path(path).resolve()
        if path not in self.cache:
            self.cache[path] = load_yaml(path)
            self.files.add(path)
        return self.cache[path]

    @staticmethod
    def pointer(doc, frag):
        node = doc
        for part in [p for p in frag.lstrip("/").split("/") if p]:
            part = part.replace("~1", "/").replace("~0", "~")
            node = node[int(part)] if isinstance(node, list) else node[part]
        return node

    def resolve(self, node, doc, base, stack=()):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                file_part, _, frag = ref.partition("#")
                if file_part:
                    tbase = (base.parent / file_part).resolve()
                    tdoc = self.load(tbase)
                else:
                    tbase, tdoc = base, doc
                key = (str(tbase), frag)
                if key in stack or len(stack) > self.MAX_DEPTH:
                    return {}  # recursive schema: cut the cycle
                return self.resolve(self.pointer(tdoc, frag), tdoc, tbase, stack + (key,))
            return {k: self.resolve(v, doc, base, stack) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, doc, base, stack) for v in node]
        return node

    def full(self):
        raw = self.load(self.root)
        return self.resolve(raw, raw, self.root)


def load_spec(path):
    d = Deref(path)
    spec = d.full()
    return spec, sorted(f for f in d.files if f != d.root)


def operations(spec):
    """Yield dicts describing each operation, with merged parameters."""
    for path, item in (spec.get("paths") or {}).items():
        shared = item.get("parameters", [])
        for method in HTTP_METHODS:
            op = item.get(method)
            if not op:
                continue
            params = {(p["in"], p["name"]): p for p in shared}
            params.update({(p["in"], p["name"]): p for p in op.get("parameters", [])})
            yield {
                "operationId": op.get("operationId"),
                "method": method.upper(),
                "path": path,
                "op": op,
                "parameters": list(params.values()),
                "security": op.get("security", spec.get("security")),
            }


def oidc_requirements(spec, security):
    """Return (scopes, has_oidc_scheme, alternatives) from an OAS security list."""
    schemes = (spec.get("components") or {}).get("securitySchemes", {})
    scopes, usable, alts = [], False, 0
    for req in security or []:
        req_ok = False
        for name, req_scopes in req.items():
            s = schemes.get(name, {})
            is_bearer = s.get("type") == "http" and s.get("scheme", "").lower() == "bearer"
            if s.get("type") in ("oauth2", "openIdConnect") or is_bearer:
                req_ok = True
                for sc in req_scopes:
                    if sc not in scopes:
                        scopes.append(sc)
        if req_ok:
            usable = True
            alts += 1
    return scopes, usable, alts


def route_regex_path(prefix, oas_path):
    """`/pet/{id}` -> `~/prefix(?<rest>/pet/(?<id>[^/]+)/?)$` (Kong regex route)."""
    out = []
    for part in re.split(r"(\{[^}]+\})", oas_path):
        if part.startswith("{") and part.endswith("}"):
            out.append("(?<%s>[^/]+)" % re.sub(r"\W", "_", part[1:-1]))
        else:
            out.append(re.escape(part))
    body = "".join(out)
    if body != "/":
        body = body.rstrip("/") + "/?"
    return "~" + re.escape(prefix) + "(?<rest>" + body + ")$"


def regex_path_to_oas(prefix, regex):
    """Inverse of route_regex_path, used by the policy check (5.5)."""
    s = regex[1:] if regex.startswith("~") else regex
    pre = re.escape(prefix) + "(?<rest>"
    if not s.startswith(pre) or not s.endswith(")$"):
        return None
    body = s[len(pre):-2]
    if body.endswith("/?"):
        body = body[:-2] or "/"
    body = re.sub(r"\(\?<(\w+)>\[\^/\]\+\)", r"{\1}", body)
    return re.sub(r"\\(.)", r"\1", body)


def walk_strings(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk_strings(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_strings(v, path + (str(i),))
    elif isinstance(node, str):
        yield path, node


def dump_json(path, data):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
