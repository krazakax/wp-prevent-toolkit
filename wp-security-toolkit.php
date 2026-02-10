<?php
/**
 * Plugin Name: WP Security Toolkit
 * Description: Consolidated security toolkit loader for WordPress hardening controls.
 * Version: 1.1.0
 * Author: LeverageIT
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! defined('WPST_PLUGIN_FILE')) {
	define('WPST_PLUGIN_FILE', __FILE__);
}

if (! function_exists('wpst_get_allowed_deactivation_domains')) {
	/**
	 * Get normalized allowlisted email domains for deactivation rights.
	 *
	 * @return array<int, string>
	 */
	function wpst_get_allowed_deactivation_domains(): array {
		$domains = apply_filters('wpst_deactivation_allowed_domains', ['leverage.it']);
		if (! is_array($domains)) {
			return ['leverage.it'];
		}

		$normalized = [];
		foreach ($domains as $domain) {
			if (! is_string($domain)) {
				continue;
			}

			$domain = strtolower(trim($domain));
			$domain = ltrim($domain, '@');

			if ('' === $domain) {
				continue;
			}

			$normalized[] = $domain;
		}

		$normalized = array_values(array_unique($normalized));
		if ([] === $normalized) {
			return ['leverage.it'];
		}

		return $normalized;
	}
}

if (! function_exists('wpst_current_user_email_domain')) {
	/**
	 * Get current user email domain (normalized), or empty string when unavailable.
	 */
	function wpst_current_user_email_domain(): string {
		$user = wp_get_current_user();
		if (! ($user instanceof WP_User) || 0 === (int) $user->ID) {
			return '';
		}

		$email = strtolower(trim((string) $user->user_email));
		if ('' === $email || false === strpos($email, '@')) {
			return '';
		}

		$parts = explode('@', $email);
		$domain = (string) end($parts);

		return trim($domain);
	}
}

if (! function_exists('wpst_is_domain_allowed')) {
	/**
	 * Check whether the provided domain is allowlisted.
	 *
	 * @param array<int, string> $allowed_domains
	 */
	function wpst_is_domain_allowed(string $domain, array $allowed_domains): bool {
		$domain = strtolower(trim($domain));
		if ('' === $domain) {
			return false;
		}

		foreach ($allowed_domains as $allowed_domain) {
			if (! is_string($allowed_domain) || '' === trim($allowed_domain)) {
				continue;
			}

			if ($domain === strtolower(trim($allowed_domain))) {
				return true;
			}
		}

		return false;
	}
}

if (! function_exists('wpst_deactivation_capability')) {
	/**
	 * Required capability to manage plugin deactivation in current admin context.
	 */
	function wpst_deactivation_capability(): string {
		if (is_multisite() && is_network_admin()) {
			return 'manage_network_plugins';
		}

		return 'activate_plugins';
	}
}

if (! function_exists('wpst_current_user_can_deactivate_toolkit')) {
	/**
	 * Whether current execution context is authorized to deactivate toolkit.
	 */
	function wpst_current_user_can_deactivate_toolkit(): bool {
		if (defined('WP_CLI') && WP_CLI) {
			return (bool) apply_filters('wpst_allow_wp_cli_deactivation', false);
		}

		$required_cap = wpst_deactivation_capability();
		if (! current_user_can($required_cap)) {
			return false;
		}

		$domain = wpst_current_user_email_domain();
		$allowed_domains = wpst_get_allowed_deactivation_domains();

		return wpst_is_domain_allowed($domain, $allowed_domains);
	}
}

if (! function_exists('wpst_block_deactivation_request')) {
	/**
	 * Stop unauthorized deactivation requests with a clear error message.
	 */
	function wpst_block_deactivation_request(): void {
		wp_die(
			esc_html__('This plugin can only be deactivated by authorized LeverageIT administrators.', 'wp-security-toolkit'),
			esc_html__('Forbidden', 'wp-security-toolkit'),
			[
				'response' => 403,
			]
		);
	}
}

if (! function_exists('wpst_filter_plugin_action_links')) {
	/**
	 * Remove deactivate links for unauthorized users.
	 *
	 * @param array<int|string, string> $actions
	 * @return array<int|string, string>
	 */
	function wpst_filter_plugin_action_links(array $actions): array {
		if (wpst_current_user_can_deactivate_toolkit()) {
			return $actions;
		}

		unset($actions['deactivate']);

		return $actions;
	}
}

if (! function_exists('wpst_show_deactivation_notice')) {
	/**
	 * Show informational notice to unauthorized users on plugin screens.
	 */
	function wpst_show_deactivation_notice(): void {
		global $pagenow;
		if ('plugins.php' !== $pagenow) {
			return;
		}

		if (wpst_current_user_can_deactivate_toolkit()) {
			return;
		}

		echo '<div class="notice notice-warning"><p>';
		echo esc_html__('This plugin can only be deactivated by authorized LeverageIT administrators.', 'wp-security-toolkit');
		echo '</p></div>';
	}
}

if (! function_exists('wpst_intercept_deactivation_requests')) {
	/**
	 * Block single and bulk deactivation requests for unauthorized users.
	 */
	function wpst_intercept_deactivation_requests(): void {
		global $pagenow;
		if ('plugins.php' !== $pagenow) {
			return;
		}

		if (defined('WP_CLI') && WP_CLI) {
			return;
		}

		$plugin_basename = plugin_basename(WPST_PLUGIN_FILE);
		$action = isset($_REQUEST['action']) ? sanitize_key((string) wp_unslash($_REQUEST['action'])) : '';
		$action2 = isset($_REQUEST['action2']) ? sanitize_key((string) wp_unslash($_REQUEST['action2'])) : '';
		$bulk_action = '';

		if ('' !== $action && '-1' !== $action) {
			$bulk_action = $action;
		} elseif ('' !== $action2 && '-1' !== $action2) {
			$bulk_action = $action2;
		}

		$single_plugin = isset($_REQUEST['plugin']) ? plugin_basename(sanitize_text_field((string) wp_unslash($_REQUEST['plugin']))) : '';
		if ('deactivate' === $action && $plugin_basename === $single_plugin) {
			check_admin_referer('deactivate-plugin_' . $plugin_basename);

			if (! current_user_can(wpst_deactivation_capability()) || ! wpst_current_user_can_deactivate_toolkit()) {
				wpst_block_deactivation_request();
			}
		}

		if (! in_array($bulk_action, ['deactivate-selected', 'deactivate'], true)) {
			return;
		}

		$checked = isset($_REQUEST['checked']) ? (array) wp_unslash($_REQUEST['checked']) : [];
		$plugins = array_map(
			static function ($item): string {
				return plugin_basename(sanitize_text_field((string) $item));
			},
			$checked
		);

		if (! in_array($plugin_basename, $plugins, true)) {
			return;
		}

		check_admin_referer('bulk-plugins');

		if (! current_user_can(wpst_deactivation_capability()) || ! wpst_current_user_can_deactivate_toolkit()) {
			wpst_block_deactivation_request();
		}
	}
}

if (! function_exists('wpst_prevent_unauthorized_option_deactivation')) {
	/**
	 * Prevent unauthorized plugin deactivation via option updates.
	 *
	 * @param array<int, string> $value
	 * @param array<int, string> $old_value
	 * @return array<int, string>
	 */
	function wpst_prevent_unauthorized_option_deactivation(array $value, array $old_value): array {
		$plugin_basename = plugin_basename(WPST_PLUGIN_FILE);

		if (! in_array($plugin_basename, $old_value, true)) {
			return $value;
		}

		if (in_array($plugin_basename, $value, true)) {
			return $value;
		}

		if (wpst_current_user_can_deactivate_toolkit()) {
			return $value;
		}

		return $old_value;
	}
}

if (! function_exists('wpst_prevent_unauthorized_sitewide_deactivation')) {
	/**
	 * Prevent unauthorized network deactivation via site option updates.
	 *
	 * @param array<string, int|string> $value
	 * @param array<string, int|string> $old_value
	 * @return array<string, int|string>
	 */
	function wpst_prevent_unauthorized_sitewide_deactivation(array $value, array $old_value): array {
		$plugin_basename = plugin_basename(WPST_PLUGIN_FILE);

		if (! array_key_exists($plugin_basename, $old_value)) {
			return $value;
		}

		if (array_key_exists($plugin_basename, $value)) {
			return $value;
		}

		if (wpst_current_user_can_deactivate_toolkit()) {
			return $value;
		}

		return $old_value;
	}
}

$plugin_basename = plugin_basename(WPST_PLUGIN_FILE);
add_filter('plugin_action_links_' . $plugin_basename, 'wpst_filter_plugin_action_links');
add_filter('network_admin_plugin_action_links_' . $plugin_basename, 'wpst_filter_plugin_action_links');
add_action('admin_init', 'wpst_intercept_deactivation_requests');
add_action('admin_notices', 'wpst_show_deactivation_notice');
add_action('network_admin_notices', 'wpst_show_deactivation_notice');
add_filter('pre_update_option_active_plugins', 'wpst_prevent_unauthorized_option_deactivation', 10, 2);
add_filter('pre_update_site_option_active_sitewide_plugins', 'wpst_prevent_unauthorized_sitewide_deactivation', 10, 2);
add_action('plugins_loaded', 'wpst_maybe_upgrade_database', 1);


if (! function_exists('wpst_install_or_upgrade_database')) {
	function wpst_install_or_upgrade_database(): void {
		require_once __DIR__ . '/modules/rate-limiter-events.php';
		WPST_Rate_Limiter_Events::activate();
	}
}

if (! function_exists('wpst_activate_plugin')) {
	function wpst_activate_plugin(): void {
		wpst_install_or_upgrade_database();
	}
}

if (! function_exists('wpst_maybe_upgrade_database')) {
	function wpst_maybe_upgrade_database(): void {
		require_once __DIR__ . '/modules/rate-limiter-events.php';

		$current_version = (string) get_option(WPST_Rate_Limiter_Events::DB_VERSION_OPTION, '0');
		if (version_compare($current_version, WPST_Rate_Limiter_Events::DB_VERSION, '>=')) {
			WPST_Rate_Limiter_Events::ensure_cleanup_schedule();
			return;
		}

		wpst_install_or_upgrade_database();
	}
}

register_activation_hook(WPST_PLUGIN_FILE, 'wpst_activate_plugin');

require_once __DIR__ . '/loader.php';
