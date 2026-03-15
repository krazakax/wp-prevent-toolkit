# WP Security Toolkit

This repository now includes a practical blueprint for building a modern, lightweight, and security-hardened CMS (WordPress-inspired, but without unnecessary bloat).

## CMS Blueprint Docs
- Product specification: `docs/cms-product-spec.md`
- Technical architecture: `docs/cms-technical-architecture.md`

## Existing WordPress Toolkit Modules
- `modules/security-headers-baseline.php`
- `modules/file-lockdown.php`
- `modules/uploads-execution-guard.php`
- `modules/rest-user-privacy.php`
- `modules/admin-domain-guard.php`
- `modules/rate-limiter.php`
- `modules/xmlrpc-guard.php`
- `modules/rate-limiter-events.php`
- `modules/diagnostics-dashboard.php`
- `modules/admin-menu.php`
- `modules/cms-manager.php`

## Install from GitHub ZIP
Download ZIP from GitHub → Upload Plugin in WordPress (`Plugins` → `Add New` → `Upload Plugin`) → Activate.

## Codex / AI Agent Implementation Guidance
- If an AI coding agent (including Codex) is used for scaffolding or frontend examples in this repository, it should use **React** with **Next.js** only.
- Do not introduce alternative frontend frameworks (for example Vue, Angular, Svelte, Remix, Nuxt, or Gatsby) in agent-generated proposals unless explicitly requested by a human maintainer.


## CMS Capabilities Added
- Admin CMS manager screen for user creation and role assignment.
- Quick-create forms for Pages and Posts.
- SEO meta box on Pages and Posts (title, description, robots, canonical URL).
- CMS settings screen for site title, tagline, and related publishing defaults.
- Blog shortcodes for archive and single-post rendering (`[wpst_blog_archive]`, `[wpst_blog_single id="123"]`).
- One-click sample page generator for starter Home and Login pages (`[wpst_login_form]` included on Login).
