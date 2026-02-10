<?php
/**
 * Plugin Name: WP Security Toolkit - REST User Privacy Guard
 * Description: Blocks common user enumeration vectors while preserving normal REST API usage.
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Rest_User_Privacy_Guard')) {
	final class WPST_Rest_User_Privacy_Guard {
		public function init(): void {
			add_action('template_redirect', [$this, 'handle_author_enumeration_guards'], 1);
			add_filter('rest_authentication_errors', [$this, 'restrict_rest_user_endpoints']);
		}

		public function handle_author_enumeration_guards(): void {
			if (is_admin() || (function_exists('wp_doing_ajax') && wp_doing_ajax())) {
				return;
			}

			if ($this->should_block_numeric_author_query()) {
				$this->send_block_response();
			}

			$block_author_archives = (bool) apply_filters('wpst_block_author_archives', true);
			if ($block_author_archives && is_author()) {
				$this->send_block_response();
			}
		}

		/**
		 * @param null|bool|\WP_Error $result
		 * @return null|bool|\WP_Error
		 */
		public function restrict_rest_user_endpoints($result) {
			if ($result instanceof \WP_Error) {
				return $result;
			}

			$restrict = (bool) apply_filters('wpst_rest_restrict_users_endpoints', true);
			if (! $restrict || ! $this->is_rest_users_request()) {
				return $result;
			}

			$required_capability = (string) apply_filters('wpst_rest_users_required_capability', 'list_users');
			$required_capability = '' !== trim($required_capability) ? $required_capability : 'list_users';

			if (! is_user_logged_in()) {
				return new \WP_Error(
					'wpst_rest_users_unauthorized',
					__('Authentication required to access user endpoints.', 'wp-security-toolkit'),
					['status' => 401]
				);
			}

			if (! current_user_can($required_capability)) {
				return new \WP_Error(
					'wpst_rest_users_forbidden',
					__('You are not allowed to access user endpoints.', 'wp-security-toolkit'),
					['status' => 403]
				);
			}

			return $result;
		}

		private function should_block_numeric_author_query(): bool {
			$block_query = (bool) apply_filters('wpst_block_author_enum_query', true);
			if (! $block_query || ! isset($_GET['author']) || ! is_scalar($_GET['author'])) {
				return false;
			}

			$author_value = trim((string) $_GET['author']);
			return 1 === preg_match('/^\d+$/', $author_value);
		}

		private function send_block_response(): void {
			$mode = (string) apply_filters('wpst_author_enum_response_mode', '404');
			$mode = strtolower(trim($mode));

			if ('redirect' === $mode) {
				wp_safe_redirect(home_url('/'), 301);
				exit;
			}

			global $wp_query;
			if ($wp_query instanceof \WP_Query) {
				$wp_query->set_404();
			}

			status_header(404);
			nocache_headers();
			exit;
		}

		private function is_rest_users_request(): bool {
			$route = $this->detect_rest_route();
			if ('' !== $route && preg_match('#^/wp/v2/users(?:/\d+)?/?$#', $route)) {
				return true;
			}

			$request_uri = isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])
				? wp_unslash($_SERVER['REQUEST_URI'])
				: '';
			if ('' === $request_uri) {
				return false;
			}

			if (1 === preg_match('#/wp-json/wp/v2/users(?:/\d+)?(?:/)?(?:\?|$)#', $request_uri)) {
				return true;
			}

			return 1 === preg_match('#(?:\?|&)rest_route=/wp/v2/users(?:/\d+)?(?:/)?(?:&|$)#', $request_uri);
		}

		private function detect_rest_route(): string {
			if (isset($_GET['rest_route']) && is_scalar($_GET['rest_route'])) {
				$route = (string) wp_unslash($_GET['rest_route']);
				return '/' . ltrim($route, '/');
			}

			global $wp;
			if (isset($wp) && $wp instanceof \WP && isset($wp->query_vars['rest_route']) && is_string($wp->query_vars['rest_route'])) {
				return '/' . ltrim($wp->query_vars['rest_route'], '/');
			}

			return '';
		}
	}
}

add_action('muplugins_loaded', static function (): void {
	$guard = new WPST_Rest_User_Privacy_Guard();
	$guard->init();
});
