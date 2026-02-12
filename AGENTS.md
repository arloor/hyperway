# Agent Guide for hyperway

This guide defines the contribution rules for this repository.

## Scope
- Project type: Kubernetes Gateway API data plane and controller
- Language: Rust
- Workspace root: `/Users/bytedance/rust_http_proxy`
- Primary crate: `hyperway` (`hyperway/Cargo.toml`)

## Product Boundaries
- Keep this project Gateway-only.
- Do not reintroduce legacy capabilities:
1. Forward proxy
2. Static file serving
3. Legacy file-driven reverse proxy (`location.yaml` as source of truth)
4. System status pages unrelated to Gateway routing

## Kubernetes Contract (Keep Consistent)
- Gateway controllerName: `hyperway.arloor.dev/gateway-controller`
- Custom API group: `hyperway.arloor.dev`
- Snapshot CRD kind: `RouteSnapshot`
- Snapshot resource plural: `routesnapshots`
- Snapshot CRD name: `routesnapshots.hyperway.arloor.dev`

When changing any of these, update all related places in one commit:
- Rust constants and defaults (`hyperway/src/config.rs`, `hyperway/src/gateway_controller.rs`, `hyperway/src/gateway_api_k8s.rs`, `hyperway/src/gateway_api_snapshot_sync.rs`)
- Kubernetes manifests under `deploy/`
- Tests and README

## Repository Map
- `hyperway/`: data plane + controller runtime code
- `log_x/`: logging helper crate
- `deploy/`: Kubernetes manifests (CRD/RBAC/examples)
- `Dockerfile*`: container build definitions
- `README.md`: user and operator documentation

## Standard Workflow
1. Make focused changes only in required files.
2. Run checks:
- `cargo fmt`
- `cargo clippy -p hyperway --all-targets -- -D warnings`
- `cargo test -p hyperway`
3. Update docs/manifests when behavior or configuration changes.

## Coding Rules
- Follow `rustfmt` defaults.
- Prefer explicit, actionable error handling with `Result`.
- Avoid panics except invariant checks.
- Keep functions small and readable.
- Add comments only for non-obvious logic.

## Testing Rules
- Add/update tests for parser behavior, API paths, and runtime reconciliation when practical.
- Keep tests deterministic and fast.
- If tests are skipped, explain the reason in the final response.

## Operational Safety
- Do not log secrets or full sensitive payloads.
- Keep TLS handling compatible with Kubernetes Secret keys `tls.crt` and `tls.key`.
- Preserve backward compatibility intentionally; if behavior changes, document migration steps.

## Agent Safety Defaults
- Never run destructive commands unless explicitly requested.
- Never revert or delete user-authored changes you did not make.
- If unexpected unrelated changes are detected, stop and ask before proceeding.
