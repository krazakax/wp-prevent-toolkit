<?php

declare(strict_types=1);

if (! defined('ABSPATH') || ! defined('WPINC')) {
	exit;
}

if (! class_exists('WPST_XMLRPC_Guard')) {
	final class WPST_XMLRPC_Guard {
		private bool $initialized = false;

		public function init(): void {
			if ($this->initialized) {
				return;
			}

			$this->initialized = true;

			add_filter('xmlrpc_enabled', [$this, 'filter_xmlrpc_enabled'], 5);
			add_filter('xmlrpc_methods', [$this, 'filter_xmlrpc_methods']);
			add_action('parse_request', [$this, 'block_direct_xmlrpc_requests'], 0);
		}

		/**
		 * Filter whether XML-RPC is enabled.
		 *
		 * Sites can override this with the `wpst_xmlrpc_enabled` filter.
		 */
		public function filter_xmlrpc_enabled(bool $enabled): bool {
			if ((bool) apply_filters('wpst_xmlrpc_enabled', false)) {
				return $enabled;
			}

			return false;
		}

		/**
		 * Disable pingback XML-RPC methods when requested.
		 *
		 * @param array<string, string> $methods XML-RPC method callbacks.
		 * @return array<string, string>
		 */
		public function filter_xmlrpc_methods(array $methods): array {
			$disable_pingbacks = (bool) apply_filters('wpst_xmlrpc_disable_pingbacks', true);
			if (! $disable_pingbacks) {
				return $methods;
			}

			unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);

			return $methods;
		}

		public function block_direct_xmlrpc_requests(): void {
			if ((defined('WP_CLI') && WP_CLI) || ! (bool) apply_filters('wpst_xmlrpc_block_direct_requests', true)) {
				return;
			}

			$request_uri = isset($_SERVER['REQUEST_URI']) && is_scalar($_SERVER['REQUEST_URI'])
				? sanitize_text_field((string) wp_unslash($_SERVER['REQUEST_URI']))
				: '';
			if ('' === $request_uri) {
				return;
			}

			$path = wp_parse_url($request_uri, PHP_URL_PATH);
			$path = is_string($path) ? strtolower(untrailingslashit($path)) : '';
			if ('/xmlrpc.php' !== $path) {
				return;
			}

			status_header(403);
			nocache_headers();
			wp_die(
				esc_html__('XML-RPC access is disabled.', 'wp-security-toolkit'),
				esc_html__('Forbidden', 'wp-security-toolkit'),
				['response' => 403]
			);
		}
	}
}

$bootstrap = static function (): void {
	$guard = new WPST_XMLRPC_Guard();
	$guard->init();
};

if (did_action('muplugins_loaded')) {
	$bootstrap();
} else {
	add_action('plugins_loaded', $bootstrap);
}
