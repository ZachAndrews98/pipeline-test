# OAS-to-Konnect Pipeline

GitHub Actions pipeline that converts an approved OpenAPI contract into Konnect Gateway Terraform
resources and promotes the same generated artifact `dev` -> `uat` -> `prod-internal` -> `prod-external`.
Implements Phase 4 (and the Phase 5 gates) of *Konnect Dedicated Cloud Gateway Setup Tasks.md*,
using the rules in *Kong API Lifecycle Deployment Scenarios.md*. Tooling choice (Task 0.7): **Terraform**
(`kong/konnect` provider), matching the existing `kong-ai-mcp-apiops` repo.

## Layout

```
.github/workflows/
  oas-to-konnect.yaml     prepare -> build (lint, classify, generate, gates) -> deploy chain
  deploy-target.yaml      reusable: plan -> approval -> apply -> snapshots -> smoke tests -> tag
manifests/                one deployment manifest per API major (Task 4.2)
specs/                    OAS contracts + referenced JSON Schemas, in VCS (Task 4.1)
environments/             per-control-plane platform parameters (Task 4.11)
policy/                   allow-list, ownership registry, EA approvals, Spectral ruleset
scripts/
  oas2tf.py               generator: OAS + manifest + env -> Terraform JSON (Tasks 4.3-4.10, 4.16)
  policy_check.py         pipeline gates 5.1-5.11
  plan_guard.py           scoped-apply guard on the Terraform plan (4.13)
  plan_matrix.py          which manifests deploy to which targets
  smoke_test.py           OAS-derived contract/smoke tests per regional data plane (7.2-7.8)
```

GitHub only runs workflows from `<repo root>/.github/workflows/`, so this repo's layout is the repo root.

## Flow

```
PR / push to main / manual dispatch
prepare   pick manifests + targets, config revision = git SHA (4.16)
build     per manifest: Spectral lint -> oasdiff vs last prod-deployed contract -> policy gates (pre)
          -> generate Terraform for each target -> policy gates (post) -> terraform validate
          -> upload ONE artifact (config-<manifest>)
deploy-dev -> deploy-uat -> deploy-prod-internal -> deploy-prod-external
          each: plan (summary + plan guard) -> [environment approval] -> apply exact saved plan
                -> before/after state snapshots -> smoke tests in BOTH regions -> tag (prod only)
```

- Pull requests: build + **plan against dev** (reviewable diff, nothing applied).
- Push to `main`: dev and uat apply automatically; prod jobs wait on GitHub Environment reviewers.
- Mocks (`backend.mode: mock|mixed`) stop after UAT; the planner never schedules them for prod (D-03).
- `prod-external` runs only after `prod-internal` (T2, D-15); `exposure: internal` APIs never get it (D-20a).
- Manual dispatch: choose manifest, single target or `promotion`, `plan`/`apply`.
  **Rollback (10.1):** dispatch with `ref` = last known-good commit, `mode: apply`, `rollback: true`.
  **Dev branch deploy (D-18):** dispatch from the branch with `branch_deploy: true`. Routes live under
  `/branch-<slug>/{api}/v{major}/...` on a branch-suffixed Service with its own state; closing the PR
  destroys only that branch's entities.

## What the generator emits (per target, per variant)

One Terraform root per `(api, target, variant)` with its own state key, so an apply can only touch that API (C1).

| Entity | Details |
| --- | --- |
| Service `{domain}-{api}-v{major}-{int\|ext}` | upstream from `manifest.targets.<env>.upstream`; placeholder `mock.invalid` for mocks |
| Route `{service}-{operationId}` | one per operation (D-09 default); host from `environments/<env>.yaml` |
| `openid-connect` (per Route) | issuer from env, audience from manifest target, scopes from OAS `security`, roles from `x-required-roles` |
| `request-validator` (per Route) | draft-4 body and parameter schemas derived from the OAS |
| `response-transformer` | `API-Version`, `X-Config-Revision`, and `X-Mock-Response` when mocked |
| `rate-limiting`, `correlation-id`, `http-log` | Service-scoped baseline; values from the env file |
| `mocking` | mock/mixed only; spec is dereferenced and its paths re-prefixed to the gateway path |
| `request-transformer` | strips the gateway prefix and applies the backend base path (live routes) |
| Tags on every entity | `api`, `api-major`, `api-version`, `exposure`, `owner`, `lifecycle`, `env`, `backend` (+ `config-revision`, `managed-by`, `branch`) |

Routes are regex paths (`~/contracts/v1(?<rest>/contracts/(?<id>[^/]+)/?)$`) with `strip_path=false`, and the
upstream path is rebuilt from the capture. This is deliberate: `strip_path` on a regex Route strips the whole
match. Only target-specific values vary between environments (Principle 4).

## Policy gates (`scripts/policy_check.py`)

| # | Gate | # | Gate |
| --- | --- | --- | --- |
| 5.1 | Naming and required tags | 5.7 | Target matches approved exposure |
| 5.2 | Required plugins (effective = Service + `global_plugins`) | 5.8 | No mocks / placeholder upstreams in prod |
| 5.3 | Plugin allow-list | 5.9 | Path/hostname conflicts + ownership registry |
| 5.4 | No plaintext secrets (vault refs only) | 5.10 | EA approval matches exact spec + schema hashes |
| 5.5 | Routes == contract; path major == contract major | 5.11 | oasdiff classification + recorded team determination |
| 5.6 | One correct IdP per variant (Entra ID / External ID) | | |

## One-time setup

1. **GitHub Environments:** `dev`, `uat`, `prod-internal`, `prod-internal-plan`, `prod-external`, `prod-external-plan`.
   Put required reviewers on `prod-internal` and `prod-external` only; the `-plan` twins hold the same
   credentials without reviewers so approvers can read the plan first.
2. **Per environment** - secrets: `KONNECT_SPAT` (system account scoped to that control plane only, C18),
   `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET`, `TEST_SCOPE`, optional `WRONG_ISSUER_TOKEN`, `LOW_SCOPE_TOKEN`.
   Variables: `KONNECT_CONTROL_PLANE_ID`, `TFSTATE_RESOURCE_GROUP`, `TFSTATE_STORAGE_ACCOUNT`,
   `TFSTATE_CONTAINER`, `ARM_CLIENT_ID`, `ARM_TENANT_ID`, `ARM_SUBSCRIPTION_ID` (state via Azure OIDC, no stored keys).
3. Fill in `environments/*.yaml` (issuers, hostnames, regional data-plane addresses, global plugins).
4. Add CODEOWNERS: `policy/ea-approvals.yaml` -> EA, `policy/ownership-registry.yaml` and
   `policy/plugin-allowlist.yaml` -> CPT, `environments/` -> CPT.

## Onboarding an API

1. Add the contract (and schemas) under `specs/<api>/`; every operation needs an `operationId`, an OAuth2/OIDC
   `security` requirement, and (for mocks) a 2xx response example.
2. Copy `manifests/legal-contracts-v1.yaml`; set `semver` equal to `info.version`.
3. Register the path prefix and owner in `policy/ownership-registry.yaml`.
4. EA runs `python scripts/policy_check.py --manifest manifests/<m>.yaml --print-hashes` and records the
   approval in `policy/ea-approvals.yaml`. Any change to the spec or schemas invalidates it (D-24).
5. Open a PR; review the dev plan in the job summary.

## Assumptions and items to confirm

- **Samples:** the contract, manifest, hostnames, tenants, and the entry in `ea-approvals.yaml` are placeholders.
- **Backend state:** Azure Storage (`azurerm`), following the suggestion already in `kong-ai-mcp-apiops/terraform/envs/dev/backend.tf`. Swap the `backend` block in `oas2tf.py` and the `-backend-config` flags if Williams picks another.
- **Verified locally:** generated config passes `terraform validate` against the real `kong/konnect` provider schema, and the policy gates, plan guard, and generator were exercised for mock, live, `both`, and branch cases. The workflows themselves were not run (they need your Konnect org and GitHub Environments), and `actionlint` was not available.
- **Mocking plugin** matching on a prefixed path should be confirmed in dev (Task 6A.3); the generator re-prefixes the spec paths to match the gateway path.
- **`scopes_required`:** when an operation lists several alternative security requirements, scopes are merged. Confirm the plugin's match semantics against D-08/D-23 before relying on OR behaviour.
- **Gateway-generated error headers (7.3):** `response-transformer` may not decorate responses the OIDC plugin short-circuits; the smoke tests do not assert it. Verify and, if required, add a global header plugin.
- **Both-or-restore (C15):** if `prod-external` fails after `prod-internal` succeeded, restoration is a manual rollback dispatch; it is not automated.
- **Open decisions** still parameters here: D-09 (Route per operation only), D-12 (hostnames), D-17 (`rate_limit.policy` defaults to `local`), D-23 (portal/catalog linking is Phase 8 and out of scope).
- Phase 8 (Catalog/Portal) and drift detection (10.2) are not part of this workflow.
