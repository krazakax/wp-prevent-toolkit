<?php
/**
 * Plugin Name: WP Security Toolkit - Restrict Admin Role by Email Domain
 * Description: Prevent Administrator role assignment unless the user's email domain is allowlisted.
 * Version: 1.2.0
 * Author: WP Security Toolkit
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

final class WPST_Restrict_Admin_By_Domain
{
    /**
     * Allowlisted domains.
     *
     * Supports exact domains and wildcard subdomains:
     * - leverage.it
     * - *.leverage.it
     *
     * @return list<string>
     */
    private function allowed_domains(): array
    {
        $defaults = [
            'leverage.it',
            'laurelbaycapital.com',
        ];

        $domains = apply_filters('wpst_allowed_admin_email_domains', $defaults);

        if (!is_array($domains)) {
            return [];
        }

        $normalized = array_values(array_filter(array_map([$this, 'normalize_domain'], $domains)));

        return array_values(array_unique($normalized));
    }

    /**
     * Role to downgrade to if administrator is disallowed.
     */
    private function fallback_role(): string
    {
        $role = apply_filters('wpst_disallowed_admin_fallback_role', 'subscriber');
        $role = is_string($role) ? sanitize_key($role) : 'subscriber';

        if ($role === '' || !get_role($role)) {
            return 'subscriber';
        }

        return $role;
    }

    /**
     * Whether wildcard root match is allowed.
     * Example: '*.example.com' also matching 'example.com'. Defaults false.
     */
    private function wildcard_includes_root(): bool
    {
        return (bool) apply_filters('wpst_wildcard_includes_root_domain', false);
    }

    private function normalize_domain($domain): string
    {
        $domain = strtolower(trim((string) $domain));
        $domain = ltrim($domain, '@');

        if (str_starts_with($domain, '*.')) {
            $rest = trim(substr($domain, 2));
            $rest = $this->normalize_idn($rest);

            return $rest !== '' ? '*.' . $rest : '';
        }

        return $this->normalize_idn($domain);
    }

    private function normalize_idn(string $domain): string
    {
        $domain = strtolower(trim($domain));

        if ($domain === '') {
            return '';
        }

        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (is_string($ascii) && $ascii !== '') {
                $domain = strtolower($ascii);
            }
        }

        return trim($domain, '.');
    }

    private function email_domain($email): string
    {
        $email = strtolower(trim((string) $email));

        if (!is_email($email)) {
            return '';
        }

        $parts = explode('@', $email);
        $domain = (string) end($parts);

        return $this->normalize_idn($domain);
    }

    private function domain_is_allowed(string $domain): bool
    {
        if ($domain === '') {
            return false;
        }

        foreach ($this->allowed_domains() as $allowed_domain) {
            if ($allowed_domain === $domain) {
                return true;
            }

            if (!str_starts_with($allowed_domain, '*.')) {
                continue;
            }

            $root = substr($allowed_domain, 2);

            if ($root === '') {
                continue;
            }

            if ($this->wildcard_includes_root() && $domain === $root) {
                return true;
            }

            if (str_ends_with($domain, '.' . $root)) {
                return true;
            }
        }

        return false;
    }

    private function email_is_allowed_for_admin($email): bool
    {
        return $this->domain_is_allowed($this->email_domain($email));
    }

    /**
     * UI enforcement when editing/creating users in wp-admin.
     */
    public function validate_profile_role($errors, bool $update, $user)
    {
        unset($update);

        if (!is_admin() || !($errors instanceof WP_Error)) {
            return $errors;
        }

        $requested_role = isset($_POST['role']) ? sanitize_key(wp_unslash($_POST['role'])) : '';
        if ($requested_role !== 'administrator') {
            return $errors;
        }

        $email = '';
        if ($user instanceof WP_User) {
            $email = (string) $user->user_email;
        } elseif (is_object($user) && isset($user->user_email)) {
            $email = (string) $user->user_email;
        }

        if (!$this->email_is_allowed_for_admin($email)) {
            $errors->add(
                'wpst_restricted_admin_domain',
                __('Administrator role is restricted for this site. Your email domain is not allowlisted.', 'wpst')
            );
        }

        return $errors;
    }

    /**
     * Programmatic enforcement before insert/update.
     */
    public function enforce_pre_insert(array $data, bool $update, ?int $user_id, array $userdata): array
    {
        unset($update, $user_id);

        $role = $data['role'] ?? ($userdata['role'] ?? '');
        if ($role !== 'administrator') {
            return $data;
        }

        $email = $data['user_email'] ?? ($userdata['user_email'] ?? '');
        if ($this->email_is_allowed_for_admin($email)) {
            return $data;
        }

        $data['role'] = $this->fallback_role();

        if (isset($data['caps']) && is_array($data['caps'])) {
            unset($data['caps']['administrator']);
        }

        return $data;
    }

    /**
     * Backstop when role is directly set to administrator.
     */
    public function backstop_on_set_role(int $user_id, string $role, $old_roles): void
    {
        if ($role !== 'administrator') {
            return;
        }

        $user = get_userdata($user_id);
        if (!$user || $this->email_is_allowed_for_admin($user->user_email)) {
            return;
        }

        $fallback = $this->fallback_role();
        $prev = (is_array($old_roles) && !empty($old_roles)) ? sanitize_key((string) reset($old_roles)) : '';
        $target = ($prev !== '' && get_role($prev)) ? $prev : $fallback;

        remove_action('set_user_role', [$this, 'backstop_on_set_role'], 10);
        $user->set_role($target);
        add_action('set_user_role', [$this, 'backstop_on_set_role'], 10, 3);
    }

    /**
     * Demote if an admin changes their email to a disallowed domain.
     */
    public function enforce_on_profile_update(int $user_id, WP_User $old_user_data): void
    {
        unset($old_user_data);

        $user = get_userdata($user_id);
        if (!$user) {
            return;
        }

        if (!in_array('administrator', (array) $user->roles, true)) {
            return;
        }

        if ($this->email_is_allowed_for_admin($user->user_email)) {
            return;
        }

        remove_action('profile_update', [$this, 'enforce_on_profile_update'], 10);
        $user->set_role($this->fallback_role());
        add_action('profile_update', [$this, 'enforce_on_profile_update'], 10, 2);
    }

    public function init(): void
    {
        add_filter('user_profile_update_errors', [$this, 'validate_profile_role'], 10, 3);
        add_filter('wp_pre_insert_user_data', [$this, 'enforce_pre_insert'], 10, 4);
        add_action('set_user_role', [$this, 'backstop_on_set_role'], 10, 3);
        add_action('profile_update', [$this, 'enforce_on_profile_update'], 10, 2);
    }
}

add_action('plugins_loaded', static function (): void {
    (new WPST_Restrict_Admin_By_Domain())->init();
});
