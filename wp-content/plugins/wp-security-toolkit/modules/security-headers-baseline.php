<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Security_Headers_Baseline')) {
	final class WPST_Security_Headers_Baseline {
		public function init(): void {
			add_filter('wp_headers', [$this, 'filter_wp_headers']);
		}

		/**
		 * Add conservative security headers to eligible responses.
		 *
		 * @param array<string, string> $headers
		 * @return array<string, string>
		 */
		public function filter_wp_headers(array $headers): array {
			if (headers_sent()) {
				return $headers;
			}

			$headers_enabled = (bool) apply_filters('wpst_headers_enabled', true);
			if (! $headers_enabled) {
				return $headers;
			}

			$apply_to_admin = (bool) apply_filters('wpst_headers_apply_to_admin', false);
			if (is_admin() && ! $apply_to_admin) {
				return $headers;
			}

			$is_rest_request = defined('REST_REQUEST') && true === REST_REQUEST;
			$apply_to_rest = (bool) apply_filters('wpst_headers_apply_to_rest', false);
			if ($is_rest_request && ! $apply_to_rest) {
				return $headers;
			}

			$overwrite_existing = (bool) apply_filters('wpst_headers_overwrite_existing', false);

			$headers = $this->set_header(
				$headers,
				'X-Content-Type-Options',
				'nosniff',
				$overwrite_existing
			);
			$headers = $this->set_header(
				$headers,
				'Referrer-Policy',
				'strict-origin-when-cross-origin',
				$overwrite_existing
			);

			$x_frame_options = (string) apply_filters('wpst_x_frame_options', 'SAMEORIGIN');
			$x_frame_options = strtoupper(trim($x_frame_options));
			if ('' === $x_frame_options) {
				$x_frame_options = 'SAMEORIGIN';
			}

			$headers = $this->set_header(
				$headers,
				'X-Frame-Options',
				$x_frame_options,
				$overwrite_existing
			);

			$permissions_policy = (string) apply_filters(
				'wpst_permissions_policy',
				'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()'
			);
			$permissions_policy = trim($permissions_policy);
			if ('' !== $permissions_policy) {
				$headers = $this->set_header(
					$headers,
					'Permissions-Policy',
					$permissions_policy,
					$overwrite_existing
				);
			}

			$hsts_enabled = (bool) apply_filters('wpst_hsts_enabled', false);
			if ($hsts_enabled && is_ssl()) {
				$max_age = (int) apply_filters('wpst_hsts_max_age', 15552000);
				$max_age = max(0, $max_age);

				$hsts_value = 'max-age=' . $max_age;
				if ((bool) apply_filters('wpst_hsts_include_subdomains', false)) {
					$hsts_value .= '; includeSubDomains';
				}
				if ((bool) apply_filters('wpst_hsts_preload', false)) {
					$hsts_value .= '; preload';
				}

				$headers = $this->set_header(
					$headers,
					'Strict-Transport-Security',
					$hsts_value,
					$overwrite_existing
				);
			}

			$csp_report_only_enabled = (bool) apply_filters('wpst_csp_report_only_enabled', false);
			$csp_report_only_value = trim((string) apply_filters('wpst_csp_report_only_value', ''));
			if ($csp_report_only_enabled && '' !== $csp_report_only_value) {
				$headers = $this->set_header(
					$headers,
					'Content-Security-Policy-Report-Only',
					$csp_report_only_value,
					$overwrite_existing
				);
			}

			return $headers;
		}

		/**
		 * Set a header key/value with optional overwrite behavior.
		 *
		 * @param array<string, string> $headers
		 * @return array<string, string>
		 */
		private function set_header(array $headers, string $header_name, string $header_value, bool $overwrite_existing): array {
			$existing_key = $this->find_existing_header_key($headers, $header_name);
			if (null !== $existing_key && ! $overwrite_existing) {
				return $headers;
			}

			$target_key = null !== $existing_key ? $existing_key : $header_name;
			$headers[$target_key] = $header_value;

			return $headers;
		}

		/**
		 * Find an existing header key in a case-insensitive way.
		 *
		 * @param array<string, string> $headers
		 */
		private function find_existing_header_key(array $headers, string $header_name): ?string {
			$target = strtolower($header_name);
			foreach (array_keys($headers) as $key) {
				if (strtolower((string) $key) === $target) {
					return (string) $key;
				}
			}

			return null;
		}
	}
}

add_action('muplugins_loaded', static function (): void {
	$module = new WPST_Security_Headers_Baseline();
	$module->init();
});

/**
 * Example filter usage:
 *
 * add_filter('wpst_hsts_enabled', '__return_true');
 * add_filter('wpst_hsts_include_subdomains', '__return_true');
 * add_filter('wpst_hsts_preload', '__return_true');
 *
 * add_filter('wpst_headers_apply_to_rest', '__return_true');
 *
 * add_filter('wpst_x_frame_options', static function (): string {
 *     return 'DENY';
 * });
 *
 * add_filter('wpst_csp_report_only_enabled', '__return_true');
 * add_filter('wpst_csp_report_only_value', static function (): string {
 *     return "default-src 'self'; script-src 'self' https://cdn.example.com; report-uri /csp-report";
 * });
 */
