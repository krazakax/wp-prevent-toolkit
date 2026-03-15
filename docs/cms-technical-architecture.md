# Lean CMS Technical Architecture

## 1. Architecture Style
Use a **modular monolith** first. It keeps deployment simple while enforcing strong module boundaries.

### Initial Modules
- `Identity` (auth, users, MFA, sessions)
- `Authorization` (roles, permissions, policies)
- `Content` (posts/pages/taxonomies/revisions)
- `Media` (upload, transforms, metadata)
- `Publishing` (workflow, scheduling, webhooks)
- `Themes` (templating, rendering, theme assets)
- `Plugins` (manifest, lifecycle, capability enforcement)
- `Observability` (audit logs, metrics, traces)

## 2. Domain and Data Design
- Use UUIDv7 primary keys for public entities.
- Keep content version history append-only.
- Store renderable slugs with locale awareness.
- Add optimistic locking (`version` column) on mutable content tables.

## 3. API Strategy
- Versioned API prefix (`/api/v1`).
- Cursor pagination by default.
- Strong request validation (DTO + policy checks).
- Idempotency keys for write-heavy endpoints.

## 4. Security Hardening Model
- Hardened defaults:
  - secure headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy)
  - CSRF + XSS protections
  - denied-by-default authorization policies
- Secrets managed via vault/KMS, never in source.
- Background jobs run with least privilege credentials.
- Signed plugin packages verified before install.

## 5. Performance Strategy
- Full-page cache for anonymous traffic.
- Fragment cache for dynamic blocks.
- Event-driven cache invalidation on publish/update.
- Read replicas optional after scale threshold.

## 6. Quality Gates
- Unit + feature + integration tests.
- Static analysis (PHPStan max level) and code style checks.
- SAST + dependency scan + container scan on pull requests.
- Required review checklist for auth/permission touching changes.

## 7. CI/CD Blueprint
1. Validate (lint, static analysis, tests)
2. Build immutable artifact
3. Security scans
4. Deploy to staging
5. Smoke tests
6. Manual promotion to production

## 8. Folder Convention (Suggested)
```
app/
  Modules/
    Identity/
    Authorization/
    Content/
    Media/
    Publishing/
    Themes/
    Plugins/
    Observability/
```

## 9. First 2-Week Implementation Sprint
- Create Laravel project skeleton with module folders.
- Implement auth + RBAC policies.
- Implement Posts CRUD with revisions.
- Build minimal admin UI (post list/edit/publish).
- Add Redis cache and queue wiring.
- Add CI with tests + static analysis + dependency scan.
