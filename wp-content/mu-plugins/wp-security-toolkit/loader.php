<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! defined('WPST_TOOLKIT_DIR')) {
	define('WPST_TOOLKIT_DIR', __DIR__);
}

$default_enabled_modules = [
	'file-lockdown' => true,
	'admin-domain-guard' => true,
	'rest-user-privacy' => true,
	'xmlrpc-guard' => true,
	'rate-limiter' => true,
	'diagnostics-dashboard' => true,
];

/**
 * Filters enabled WP Security Toolkit modules.
 *
 * @param array<string, bool> $default_enabled_modules Enabled state per module slug.
 */
$enabled_modules = apply_filters('wpst_enabled_modules', $default_enabled_modules);
if (! is_array($enabled_modules)) {
	$enabled_modules = $default_enabled_modules;
}

$ordered_files = [
	'file-lockdown' => 'modules/file-lockdown.php',
	'admin-domain-guard' => 'modules/admin-domain-guard.php',
	'rest-user-privacy' => 'modules/rest-user-privacy.php',
	'xmlrpc-guard' => 'modules/xmlrpc-guard.php',
	'rate-limiter' => 'modules/rate-limiter.php',
	'diagnostics-dashboard' => 'modules/diagnostics-dashboard.php',
];

/**
 * Filters WP Security Toolkit module load order.
 *
 * @param array<string, string> $ordered_files Module slug keyed paths relative to WPST_TOOLKIT_DIR.
 */
$ordered_files = apply_filters('wpst_module_load_order', $ordered_files);
if (! is_array($ordered_files)) {
	$ordered_files = [];
}

foreach ($ordered_files as $module_slug => $relative_path) {
	if (! is_string($module_slug) || ! is_string($relative_path) || '' === $module_slug || '' === $relative_path) {
		continue;
	}

	$is_enabled = $enabled_modules[$module_slug] ?? false;
	if (! $is_enabled) {
		continue;
	}

	$module_file = WPST_TOOLKIT_DIR . '/' . ltrim($relative_path, '/');
	if (! is_file($module_file) || ! is_readable($module_file)) {
		continue;
	}

	require_once $module_file;
}
