# Lean CMS Product Specification

## Vision
Build a modern CMS inspired by WordPress' usability, but with a smaller core, strict security defaults, and a performance-first architecture.

## Product Goals
- **Minimal core**: keep the default install focused on publishing workflows only.
- **Fast by default**: low TTFB, page-level caching, and optimized DB access.
- **Secure by default**: harden auth, sessions, permissions, input/output handling, and deployment posture.
- **Extensible without bloat**: plugin system with sandboxed boundaries and explicit capability grants.
- **Developer friendly**: typed APIs, clear module boundaries, automated tests, and CI/CD quality gates.

## Target Users
- Solo creators and small teams who want a self-hosted CMS.
- Agencies delivering content-heavy websites with strong security requirements.
- Developers who need modern APIs and structured content, not legacy admin complexity.

## Core MVP Features
1. **Identity & Access**
   - Email/password login with optional WebAuthn (passkeys)
   - RBAC roles: Admin, Editor, Author, Viewer
   - Optional TOTP MFA
2. **Content Engine**
   - Pages, Posts, Categories, Tags
   - Draft/Review/Published workflow
   - Revisions with diff view
3. **Media Library**
   - Image upload and metadata
   - Automatic image optimization + responsive variants
4. **Theme Layer**
   - Server-rendered theme support
   - Safe template primitives and escaping-by-default helpers
5. **API Layer**
   - Versioned REST API with token-based auth
   - Webhooks for content lifecycle events
6. **Plugin System (Controlled)**
   - Signed plugin manifests
   - Scoped capabilities (database, filesystem, network)

## Non-Functional Requirements
- **Performance**: p95 page response < 200ms for cached pages under standard load.
- **Security**: ASVS-aligned controls, CSP enabled, CSRF protection, secure cookies, audit trails.
- **Reliability**: zero-downtime deploys, automated backups, background job retries.
- **Maintainability**: typed interfaces, modular architecture, 80%+ coverage in core domains.

## Suggested Tech Stack (Modern + Practical)
- **Backend**: Laravel 11+ (PHP 8.3+), strict typing where possible
- **Frontend/Admin**: Inertia.js + Vue 3 + TypeScript + Tailwind
- **Database**: PostgreSQL 16
- **Cache/Queue**: Redis
- **Search**: Meilisearch or OpenSearch (optional at MVP)
- **Storage**: S3-compatible object storage
- **Infra**: Docker + Terraform + GitHub Actions

## Security Baseline
- Passkeys and MFA support.
- Strong password hashing (Argon2id).
- Session rotation and idle timeout.
- CSRF protection and same-site secure cookies.
- Strict output encoding and markdown/html sanitization pipeline.
- Content Security Policy with nonces.
- Signed URLs for privileged operations.
- IP-based and account-based login rate limiting.
- Audit logs for auth, role changes, and content publication.
- Dependency and container image scanning in CI.

## Release Plan
- **Phase 0**: Architecture, schema, coding standards, CI baseline.
- **Phase 1 (MVP)**: Auth, RBAC, pages/posts, media, admin UI.
- **Phase 2**: Revisions, webhooks, API versioning, plugin manifest validator.
- **Phase 3**: Multi-site, marketplace, enterprise controls.
