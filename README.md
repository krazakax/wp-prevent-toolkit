# WP Prevent Toolkit

This repository contains a drop-in **must-use plugin** to restrict WordPress `administrator` role assignment to approved email domains.

## Install

1. Copy `mu-plugins/wp-security-toolkit-admin-domain-guard.php` into your site's `wp-content/mu-plugins/` directory.
2. Confirm it appears under **Plugins → Must-Use** in wp-admin.

## What it enforces

The plugin blocks or reverses `administrator` assignment through:

- wp-admin user create/edit forms.
- Programmatic user insert/update (`wp_pre_insert_user_data`).
- Direct role changes (`set_user_role` backstop).
- Profile email changes that invalidate admin eligibility.

If blocked, users are assigned a fallback role (default: `subscriber`).

## Configuration (filters)

Add these in another mu-plugin or your theme/plugin bootstrap:

```php
<?php
add_filter('wpst_allowed_admin_email_domains', static function (array $domains): array {
    return [
        'example.com',
        '*.corp.example.com',
    ];
});

add_filter('wpst_disallowed_admin_fallback_role', static function (): string {
    return 'editor';
});

// Optional: make '*.example.com' also match 'example.com'.
add_filter('wpst_wildcard_includes_root_domain', '__return_true');
```

### Domain rules

- `example.com` → exact match only.
- `*.example.com` → subdomains only by default (`a.example.com`, `b.a.example.com`).
- With `wpst_wildcard_includes_root_domain` enabled, `*.example.com` also matches `example.com`.

## Notes

- Domains are normalized to lowercase.
- `@example.com` style entries are accepted and normalized.
- Internationalized domains are converted with `idn_to_ascii()` when the PHP intl extension is available.
