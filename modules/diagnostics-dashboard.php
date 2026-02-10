<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Diagnostics_Dashboard')) {
	final class WPST_Diagnostics_Dashboard {
		private const PAGE_SLUG = 'wpst-diagnostics';
		private const TRANSIENT_KEY = 'wpst_diagnostics_payload';
		private const CACHE_TTL = 300;
		private const REFRESH_ACTION = 'wpst_refresh_diagnostics';

		/**
		 * @var array<string, mixed>|null
		 */
		private ?array $diagnostics_cache = null;

		public function register_hooks(): void {
			add_action('admin_menu', [$this, 'register_admin_menu'], 80);
			add_action('admin_post_' . self::REFRESH_ACTION, [$this, 'handle_refresh_request']);
		}

		public function register_admin_menu(): void {
			add_submenu_page(
				'wp-security-toolkit',
				__('WP Security Toolkit — Diagnostics', 'wp-security-toolkit'),
				__('Diagnostics', 'wp-security-toolkit'),
				$this->capability(),
				self::PAGE_SLUG,
				[$this, 'render_page']
			);
		}

		public function handle_refresh_request(): void {
			if (! current_user_can($this->capability())) {
				wp_die(esc_html__('You are not allowed to refresh diagnostics.', 'wp-security-toolkit'), 403);
			}

			check_admin_referer(self::REFRESH_ACTION);
			delete_transient(self::TRANSIENT_KEY);

			$target = add_query_arg(
				[
					'page' => self::PAGE_SLUG,
					'wpst_refreshed' => '1',
				],
				admin_url('admin.php')
			);

			wp_safe_redirect($target);
			exit;
		}

		public function render_page(): void {
			if (! current_user_can($this->capability())) {
				wp_die(esc_html__('You are not allowed to view diagnostics.', 'wp-security-toolkit'), 403);
			}

			$debug_refresh_valid = $this->is_rate_limit_refresh_request_valid();

			$diagnostics = $this->get_diagnostics();
			$json = wp_json_encode($diagnostics, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
			if (! is_string($json)) {
				$json = '{}';
			}

			$refresh_url = wp_nonce_url(
				admin_url('admin-post.php?action=' . self::REFRESH_ACTION),
				self::REFRESH_ACTION
			);
			?>
			<div class="wrap">
				<h1><?php echo esc_html__('WP Security Toolkit — Diagnostics', 'wp-security-toolkit'); ?></h1>
				<?php if (isset($_GET['wpst_refreshed'])) : ?>
					<div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Diagnostics were refreshed.', 'wp-security-toolkit'); ?></p></div>
				<?php endif; ?>
				<?php if ($debug_refresh_valid) : ?>
					<div class="notice notice-info is-dismissible"><p><?php echo esc_html__('Rate limiting debug snapshot refreshed.', 'wp-security-toolkit'); ?></p></div>
				<?php endif; ?>

				<p>
					<a href="<?php echo esc_url($refresh_url); ?>" class="button button-secondary"><?php echo esc_html__('Refresh status', 'wp-security-toolkit'); ?></a>
				</p>

				<h2><?php echo esc_html__('Environment & WordPress', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_assoc_table($diagnostics['environment'] ?? []); ?>

				<h2><?php echo esc_html__('Hardening Constants', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_assoc_table($diagnostics['hardening_constants'] ?? []); ?>

				<h2><?php echo esc_html__('Modules', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_modules_table($diagnostics['modules'] ?? []); ?>

				<h2><?php echo esc_html__('Module Status Summary', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_nested_section($diagnostics['module_status'] ?? []); ?>

				<h2><?php echo esc_html__('Recent Security Findings', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_nested_section($diagnostics['recent_findings'] ?? []); ?>

				<h2><?php echo esc_html__('Server & Proxy Signals', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_assoc_table($diagnostics['server_proxy'] ?? []); ?>

				<h2><?php echo esc_html__('Rate Limiting — Recent Events', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_rate_limit_recent_events(); ?>

				<h2><?php echo esc_html__('Rate Limiting (Debug)', 'wp-security-toolkit'); ?></h2>
				<?php $this->render_rate_limiter_debug_section(); ?>

				<h2><?php echo esc_html__('Copy Diagnostics JSON', 'wp-security-toolkit'); ?></h2>
				<p><?php echo esc_html__('Use this sanitized payload for support/debugging.', 'wp-security-toolkit'); ?></p>
				<p>
					<button type="button" class="button button-primary" id="wpst-copy-diagnostics"><?php echo esc_html__('Copy Diagnostics', 'wp-security-toolkit'); ?></button>
				</p>
				<textarea id="wpst-diagnostics-json" class="large-text code" rows="18" readonly><?php echo esc_textarea($json); ?></textarea>
			</div>
			<script>
			(function () {
				var button = document.getElementById('wpst-copy-diagnostics');
				var textarea = document.getElementById('wpst-diagnostics-json');
				if (!button || !textarea || !navigator.clipboard) {
					return;
				}

				button.addEventListener('click', function () {
					navigator.clipboard.writeText(textarea.value).then(function () {
						button.textContent = '<?php echo esc_js(__('Copied', 'wp-security-toolkit')); ?>';
						window.setTimeout(function () {
							button.textContent = '<?php echo esc_js(__('Copy Diagnostics', 'wp-security-toolkit')); ?>';
						}, 1500);
					});
				});
			}());
			</script>
			<?php
		}

		private function capability(): string {
			$capability = (string) apply_filters('wpst_diagnostics_capability', 'manage_options');
			$capability = sanitize_key($capability);
			return '' !== $capability ? $capability : 'manage_options';
		}

		/**
		 * @return array<string, mixed>
		 */
		private function get_diagnostics(): array {
			if (null !== $this->diagnostics_cache) {
				return $this->diagnostics_cache;
			}

			$cached = get_transient(self::TRANSIENT_KEY);
			if (is_array($cached)) {
				$this->diagnostics_cache = $cached;
				return $this->diagnostics_cache;
			}

			$diagnostics = [
				'generated_at_utc' => gmdate('c'),
				'toolkit_version' => $this->toolkit_version(),
				'environment' => $this->environment_status(),
				'hardening_constants' => $this->hardening_constants(),
				'modules' => $this->discover_modules(),
				'module_status' => $this->module_status(),
				'recent_findings' => $this->recent_findings(),
				'server_proxy' => $this->server_proxy_signals(),
			];

			set_transient(self::TRANSIENT_KEY, $diagnostics, self::CACHE_TTL);
			$this->diagnostics_cache = $diagnostics;

			return $this->diagnostics_cache;
		}

		private function toolkit_version(): string {
			if (defined('WPST_TOOLKIT_VERSION')) {
				return (string) constant('WPST_TOOLKIT_VERSION');
			}

			$mu_loader = dirname(__DIR__) . '.php';
			if (function_exists('get_file_data') && is_readable($mu_loader)) {
				$headers = get_file_data($mu_loader, ['Version' => 'Version']);
				if (isset($headers['Version']) && is_string($headers['Version']) && '' !== trim($headers['Version'])) {
					return trim($headers['Version']);
				}
			}

			return 'unknown';
		}

		/**
		 * @return array<string, scalar>
		 */
		private function environment_status(): array {
			$environment = function_exists('wp_get_environment_type') ? (string) wp_get_environment_type() : 'unknown';
			$rest_server_available = class_exists('WP_REST_Server') || function_exists('rest_get_server');

			return [
				'environment_type' => $environment,
				'wordpress_version' => (string) get_bloginfo('version'),
				'php_version' => PHP_VERSION,
				'site_host' => $this->extract_host((string) site_url()),
				'home_host' => $this->extract_host((string) home_url()),
				'is_multisite' => is_multisite() ? 'true' : 'false',
				'is_ssl' => is_ssl() ? 'true' : 'false',
				'rest_enabled' => $rest_server_available ? 'likely' : 'unknown',
			];
		}

		/**
		 * @return array<string, scalar>
		 */
		private function hardening_constants(): array {
			return [
				'DISALLOW_FILE_EDIT' => $this->constant_state('DISALLOW_FILE_EDIT'),
				'DISALLOW_FILE_MODS' => $this->constant_state('DISALLOW_FILE_MODS'),
				'FORCE_SSL_ADMIN' => $this->constant_state('FORCE_SSL_ADMIN'),
				'WP_DEBUG' => $this->constant_state('WP_DEBUG'),
			];
		}

		/**
		 * @return array<string, array<string, string>>
		 */
		private function discover_modules(): array {
			$discovered = [];

			if (defined('WPST_ENABLED_MODULES')) {
				$from_constant = constant('WPST_ENABLED_MODULES');
				if (is_array($from_constant)) {
					foreach ($from_constant as $slug => $enabled) {
						if (! is_string($slug) || '' === $slug) {
							continue;
						}
						$discovered[$slug] = [
							'state' => (bool) $enabled ? 'enabled' : 'disabled',
							'source' => 'constant',
						];
					}
				}
			}

			if (isset($GLOBALS['wpst_enabled_modules']) && is_array($GLOBALS['wpst_enabled_modules'])) {
				foreach ($GLOBALS['wpst_enabled_modules'] as $slug => $enabled) {
					if (! is_string($slug) || '' === $slug) {
						continue;
					}
					$discovered[$slug] = [
						'state' => (bool) $enabled ? 'enabled' : 'disabled',
						'source' => 'global',
					];
				}
			}

			$default_enabled = [
				'admin-menu' => true,
				'file-lockdown' => true,
				'admin-domain-guard' => true,
				'rest-user-privacy' => true,
				'xmlrpc-guard' => true,
				'rate-limiter' => true,
				'rate-limiter-events' => true,
				'diagnostics-dashboard' => true,
				'security-headers-baseline' => true,
				'uploads-execution-guard' => true,
			];

			$enabled_modules = apply_filters('wpst_enabled_modules', $default_enabled);
			if (is_array($enabled_modules)) {
				foreach ($enabled_modules as $slug => $enabled) {
					if (! is_string($slug) || '' === $slug) {
						continue;
					}
					$discovered[$slug] = [
						'state' => (bool) $enabled ? 'enabled' : 'disabled',
						'source' => 'filter',
					];
				}
			}

			$module_dir = defined('WPST_TOOLKIT_DIR') ? (string) WPST_TOOLKIT_DIR . '/modules' : dirname(__FILE__);
			if (is_dir($module_dir)) {
				$files = scandir($module_dir);
				if (is_array($files)) {
					foreach ($files as $file) {
						if (! is_string($file) || ! str_ends_with($file, '.php')) {
							continue;
						}
						$slug = basename($file, '.php');
						if (! isset($discovered[$slug])) {
							$discovered[$slug] = [
								'state' => 'present',
								'source' => 'filesystem',
							];
						}
					}
				}
			}

			$discovered = apply_filters('wpst_diagnostics_modules', $discovered);
			if (! is_array($discovered)) {
				return [];
			}

			if (isset($discovered['xmlrpc-guard'])) {
				$xmlrpc_loaded = class_exists('WPST_XMLRPC_Guard');
				if ($xmlrpc_loaded) {
					$discovered['xmlrpc-guard']['state'] = 'enabled';
					$discovered['xmlrpc-guard']['source'] = 'file';
				} elseif ('enabled' === ($discovered['xmlrpc-guard']['state'] ?? '')) {
					$discovered['xmlrpc-guard']['state'] = 'disabled';
				}
			}

			ksort($discovered);
			return $discovered;
		}

		/**
		 * @return array<string, mixed>
		 */
		private function module_status(): array {
			$show_sensitive = (bool) apply_filters('wpst_diagnostics_show_sensitive', false);
			$allowed_domains = apply_filters('wpst_allowed_admin_email_domains', []);
			if (! is_array($allowed_domains)) {
				$allowed_domains = [];
			}

			$allowed_domains = array_values(array_filter(array_map('strval', $allowed_domains), static function (string $item): bool {
				return '' !== trim($item);
			}));

			$rest_required_cap = sanitize_key((string) apply_filters('wpst_rest_users_required_capability', 'list_users'));
			if ('' === $rest_required_cap) {
				$rest_required_cap = 'list_users';
			}

			$uploads_scan = get_option('wpst_uploads_scan_results', []);
			$uploads_files = [];
			$uploads_last_scan = 0;
			if (is_array($uploads_scan)) {
				$uploads_files = isset($uploads_scan['files']) && is_array($uploads_scan['files']) ? $uploads_scan['files'] : [];
				$uploads_last_scan = isset($uploads_scan['last_scan']) ? (int) $uploads_scan['last_scan'] : 0;
			}

			$trimmed_uploads_files = [];
			foreach (array_slice($uploads_files, 0, 20) as $file) {
				$path = str_replace('\\', '/', (string) $file);
				if ($show_sensitive) {
					$trimmed_uploads_files[] = $path;
					continue;
				}
				$trimmed_uploads_files[] = basename($path);
			}

			$htaccess_status = [
				'auto_write_enabled' => (bool) apply_filters('wpst_uploads_auto_write_htaccess', false),
				'marker_block_present' => false,
			];

			$upload_dir = wp_upload_dir(null, false);
			$upload_base = isset($upload_dir['basedir']) ? (string) $upload_dir['basedir'] : '';
			if ('' !== $upload_base) {
				$htaccess_path = trailingslashit($upload_base) . '.htaccess';
				if (is_readable($htaccess_path)) {
					$contents = file_get_contents($htaccess_path, false, null, 0, 8192);
					if (is_string($contents) && str_contains($contents, '# BEGIN WPST Uploads Guard') && str_contains($contents, '# END WPST Uploads Guard')) {
						$htaccess_status['marker_block_present'] = true;
					}
				}
			}

			$rate_settings = get_option('wpst_rate_limiter_settings', []);
			if (! is_array($rate_settings)) {
				$rate_settings = [];
			}

			return [
				'admin_domain_guard' => [
					'allowed_domain_count' => count($allowed_domains),
					'wildcard_root_includes_base_domain' => (bool) apply_filters('wpst_wildcard_includes_root_domain', false, ''),
					'fallback_role' => (string) apply_filters('wpst_disallowed_admin_fallback_role', 'subscriber'),
					'allowed_domains_sample' => $show_sensitive ? array_slice($allowed_domains, 0, 10) : [],
				],
				'rest_user_privacy_guard' => [
					'block_numeric_author_query' => (bool) apply_filters('wpst_block_author_enum_query', true),
					'block_author_archives' => (bool) apply_filters('wpst_block_author_archives', true),
					'restrict_rest_users_endpoints' => (bool) apply_filters('wpst_rest_restrict_users_endpoints', true),
					'required_capability' => $rest_required_cap,
				],
				'xmlrpc_guard' => [
					'loaded' => class_exists('WPST_XMLRPC_Guard'),
					'state_source' => class_exists('WPST_XMLRPC_Guard') ? 'file' : 'filter',
					'xmlrpc_enabled' => (bool) apply_filters('xmlrpc_enabled', true),
					'pingbacks_enabled' => ! (bool) apply_filters('wpst_xmlrpc_disable_pingbacks', true),
					'block_direct_requests' => (bool) apply_filters('wpst_xmlrpc_block_direct_requests', true),
				],
				'uploads_execution_guard' => [
					'blocked_extension_count' => count((array) apply_filters('wpst_uploads_block_extensions', [
						'php',
						'phtml',
						'phar',
						'pht',
						'php3',
						'php4',
						'php5',
						'php7',
						'php8',
						'cgi',
						'pl',
						'asp',
						'aspx',
						'jsp',
						'sh',
					])),
					'last_scan_utc' => $uploads_last_scan > 0 ? gmdate('c', $uploads_last_scan) : 'never',
					'suspicious_file_count' => count($uploads_files),
					'suspicious_files_shown' => $trimmed_uploads_files,
					'htaccess' => $htaccess_status,
				],
				'security_headers_baseline' => [
					'headers_enabled' => (bool) apply_filters('wpst_headers_enabled', true),
					'hsts_enabled' => is_ssl() ? (bool) apply_filters('wpst_hsts_enabled', false) : false,
					'hsts_max_age' => is_ssl() ? (int) apply_filters('wpst_hsts_max_age', 15552000) : 0,
					'hsts_include_subdomains' => is_ssl() ? (bool) apply_filters('wpst_hsts_include_subdomains', false) : false,
					'hsts_preload' => is_ssl() ? (bool) apply_filters('wpst_hsts_preload', false) : false,
				],
				'rate_limiter' => [
					'enabled' => (bool) apply_filters('wpst_rate_limiter_enabled', (bool) ($rate_settings['enabled'] ?? false)),
					'thresholds' => [
						'any_requests_per_min' => (int) ($rate_settings['any_requests_per_min'] ?? 300),
						'human_views_per_min' => (int) ($rate_settings['human_views_per_min'] ?? 120),
						'human_404_per_min' => (int) ($rate_settings['human_404_per_min'] ?? 30),
						'crawler_views_per_min' => (int) ($rate_settings['crawler_views_per_min'] ?? 180),
						'crawler_404_per_min' => (int) ($rate_settings['crawler_404_per_min'] ?? 60),
					],
					'blocked_ip_count_estimate' => $this->blocked_ip_count_estimate(),
				],
			];
		}

		/**
		 * @return array<string, mixed>
		 */
		private function recent_findings(): array {
			$uploads_scan = get_option('wpst_uploads_scan_results', []);
			$files = [];
			$last_scan = 0;
			if (is_array($uploads_scan)) {
				$files = isset($uploads_scan['files']) && is_array($uploads_scan['files']) ? $uploads_scan['files'] : [];
				$last_scan = isset($uploads_scan['last_scan']) ? (int) $uploads_scan['last_scan'] : 0;
			}

			$show_sensitive = (bool) apply_filters('wpst_diagnostics_show_sensitive', false);
			$limited_files = [];
			foreach (array_slice($files, 0, 20) as $file) {
				$normalized = str_replace('\\', '/', (string) $file);
				$limited_files[] = $show_sensitive ? $normalized : basename($normalized);
			}

			return [
				'uploads_scan' => [
					'last_scan_utc' => $last_scan > 0 ? gmdate('c', $last_scan) : 'never',
					'suspicious_count' => count($files),
					'suspicious_files' => $limited_files,
				],
				'rate_limiter' => [
					'blocked_ip_count_estimate' => $this->blocked_ip_count_estimate(),
				],
			];
		}

		/**
		 * @return array<string, scalar>
		 */
		private function server_proxy_signals(): array {
			$software = isset($_SERVER['SERVER_SOFTWARE']) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
			$software = '' !== $software ? mb_substr($software, 0, 80) : 'unknown';

			$trusted_proxies = [];
			$stored = get_option('wpst_rate_limiter_settings', []);
			if (is_array($stored) && isset($stored['trusted_proxies']) && is_string($stored['trusted_proxies'])) {
				$trusted_proxies = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $stored['trusted_proxies']) ?: []));
			}
			$trusted_proxies = apply_filters('wpst_rate_limiter_trusted_proxies', $trusted_proxies);
			if (! is_array($trusted_proxies)) {
				$trusted_proxies = [];
			}

			return [
				'https_detected' => is_ssl() ? 'true' : 'false',
				'client_ip_strategy' => $this->client_ip_strategy(),
				'server_software' => $software,
				'has_x_forwarded_for_header' => isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? 'true' : 'false',
				'has_cf_connecting_ip_header' => isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? 'true' : 'false',
				'trusted_proxy_count' => (string) count($trusted_proxies),
			];
		}

		private function client_ip_strategy(): string {
			$trusted = apply_filters('wpst_rate_limiter_trusted_proxies', []);
			if (! is_array($trusted) || [] === $trusted) {
				return 'REMOTE_ADDR';
			}

			if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
				return 'X-Forwarded-For (trusted proxy)';
			}

			return 'REMOTE_ADDR (trusted proxy list configured)';
		}

		private function blocked_ip_count_estimate(): int {
			global $wpdb;
			if (! isset($wpdb) || ! ($wpdb instanceof wpdb)) {
				return 0;
			}

			$option_name_like = $wpdb->esc_like('_transient_wpst_rl_block:') . '%';
			$count = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(1) FROM {$wpdb->options} WHERE option_name LIKE %s",
					$option_name_like
				)
			);

			return max(0, $count);
		}

		private function is_rate_limit_refresh_request_valid(): bool {
			if (! isset($_GET['wpst_rate_limit_refresh'])) {
				return false;
			}

			$nonce = isset($_GET['_wpnonce']) ? (string) $_GET['_wpnonce'] : '';
			return '' !== $nonce && wp_verify_nonce($nonce, 'wpst_rate_limit_debug_refresh');
		}


		private function render_rate_limit_recent_events(): void {
			if (! current_user_can('manage_options')) {
				return;
			}

			if (! class_exists('WPST_Rate_Limiter_Events')) {
				echo '<p>' . esc_html__('Rate limit event logger module is not available.', 'wp-security-toolkit') . '</p>';
				return;
			}

			$events = WPST_Rate_Limiter_Events::recent_events(50);
			if ([] === $events) {
				echo '<p>' . esc_html__('No recent rate limit events found.', 'wp-security-toolkit') . '</p>';
				return;
			}

			echo '<table class="widefat striped" style="max-width: 1200px"><thead><tr>';
			echo '<th>' . esc_html__('Created (UTC)', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Action', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Rule', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Bucket', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Country', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('IP Hash', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Path', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('User Agent', 'wp-security-toolkit') . '</th>';
			echo '</tr></thead><tbody>';

			foreach ($events as $event) {
				$event = is_array($event) ? $event : [];
				$ip_hash = (string) ($event['ip_hash'] ?? '');
				$ip_hash_short = '' !== $ip_hash ? substr($ip_hash, 0, 12) . '…' : '';
				echo '<tr>';
				echo '<td>' . esc_html((string) ($event['created_at_utc'] ?? '')) . '</td>';
				echo '<td><code>' . esc_html((string) ($event['action'] ?? '')) . '</code></td>';
				echo '<td><code>' . esc_html((string) ($event['rule'] ?? '')) . '</code></td>';
				echo '<td><code>' . esc_html((string) ($event['bucket'] ?? '')) . '</code></td>';
				echo '<td>' . esc_html((string) ($event['country'] ?? '')) . '</td>';
				echo '<td><code title="' . esc_attr($ip_hash) . '">' . esc_html($ip_hash_short) . '</code></td>';
				echo '<td><code>' . esc_html((string) ($event['path'] ?? '')) . '</code></td>';
				echo '<td>' . esc_html((string) ($event['user_agent'] ?? '')) . '</td>';
				echo '</tr>';
			}

			echo '</tbody></table>';
		}

		private function render_rate_limiter_debug_section(): void {
			if (! current_user_can('manage_options')) {
				return;
			}

			// Dev-only example:
			// add_filter('wpst_rate_limiter_debug_enabled', static function ($enabled) {
			// 	return function_exists('wp_get_environment_type') && 'development' === wp_get_environment_type();
			// });
			$debug_enabled = (bool) apply_filters('wpst_rate_limiter_debug_enabled', false);

			$refresh_url = wp_nonce_url(
				add_query_arg(
					[
						'page' => self::PAGE_SLUG,
						'wpst_rate_limit_refresh' => '1',
					],
					admin_url('admin.php')
				),
				'wpst_rate_limit_debug_refresh'
			);

			echo '<p><a href="' . esc_url($refresh_url) . '" class="button button-secondary">' . esc_html__('Refresh', 'wp-security-toolkit') . '</a></p>';

			if (! $debug_enabled) {
				echo '<p>' . esc_html__('Debug snapshot disabled. Enable via filter wpst_rate_limiter_debug_enabled.', 'wp-security-toolkit') . '</p>';
				return;
			}

			$snapshot = apply_filters('wpst_rate_limiter_debug_snapshot', null);
			if (! is_array($snapshot)) {
				echo '<p>' . esc_html__('No debug snapshot is available for this request.', 'wp-security-toolkit') . '</p>';
				return;
			}

			$summary = [
				'detected_ip' => (string) ($snapshot['detected_ip'] ?? ''),
				'user_agent_bucket' => (string) ($snapshot['user_agent_bucket'] ?? 'unknown'),
				'is_whitelisted' => ! empty($snapshot['is_whitelisted']) ? 'yes' : 'no',
				'is_blocked' => ! empty($snapshot['is_blocked']) ? 'yes' : 'no',
				'is_admin_bypassed' => ! empty($snapshot['is_admin_bypassed']) ? 'yes' : 'no',
				'current_minute_bucket' => (string) ($snapshot['current_minute_bucket'] ?? ''),
				'block_transient_key' => (string) ($snapshot['block_transient_key'] ?? ''),
				'block_expires_in_seconds' => isset($snapshot['block_expires_in_seconds']) && null !== $snapshot['block_expires_in_seconds']
					? (string) max(0, (int) $snapshot['block_expires_in_seconds'])
					: 'unknown',
			];

			$this->render_assoc_table($summary);

			$counters = isset($snapshot['counters']) && is_array($snapshot['counters']) ? $snapshot['counters'] : [];
			echo '<h3>' . esc_html__('Current Per-Minute Counters', 'wp-security-toolkit') . '</h3>';
			echo '<table class="widefat striped" style="max-width: 1100px"><thead><tr>';
			echo '<th>' . esc_html__('Type', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Value', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Transient Key', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('TTL (seconds)', 'wp-security-toolkit') . '</th>';
			echo '</tr></thead><tbody>';

			foreach ($counters as $type => $counter) {
				$counter = is_array($counter) ? $counter : [];
				$value = isset($counter['value']) ? (int) $counter['value'] : 0;
				$key = isset($counter['transient_key']) ? (string) $counter['transient_key'] : '';
				$ttl = array_key_exists('ttl_seconds', $counter) && null !== $counter['ttl_seconds'] ? (string) max(0, (int) $counter['ttl_seconds']) : 'unknown';

				echo '<tr>';
				echo '<td><code>' . esc_html((string) $type) . '</code></td>';
				echo '<td>' . esc_html((string) $value) . '</td>';
				echo '<td><code>' . esc_html($key) . '</code></td>';
				echo '<td>' . esc_html($ttl) . '</td>';
				echo '</tr>';
			}

			echo '</tbody></table>';

			echo '<h3>' . esc_html__('Settings Summary', 'wp-security-toolkit') . '</h3>';
			$settings_summary = isset($snapshot['settings_summary']) && is_array($snapshot['settings_summary']) ? $snapshot['settings_summary'] : [];
			$this->render_nested_section($settings_summary);
		}

		/**
		 * @param array<string, mixed> $rows
		 */
		private function render_assoc_table(array $rows): void {
			echo '<table class="widefat striped" style="max-width: 900px"><tbody>';
			foreach ($rows as $key => $value) {
				if (is_array($value)) {
					$value = wp_json_encode($value, JSON_UNESCAPED_SLASHES);
				}

				echo '<tr>';
				echo '<th scope="row" style="width: 280px"><code>' . esc_html((string) $key) . '</code></th>';
				echo '<td>' . esc_html((string) $value) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		/**
		 * @param array<string, mixed> $rows
		 */
		private function render_nested_section(array $rows): void {
			foreach ($rows as $title => $values) {
				echo '<h3>' . esc_html(ucwords(str_replace('_', ' ', (string) $title))) . '</h3>';
				if (is_array($values)) {
					$this->render_assoc_table($values);
					continue;
				}
				echo '<p>' . esc_html((string) $values) . '</p>';
			}
		}

		/**
		 * @param array<string, mixed> $modules
		 */
		private function render_modules_table(array $modules): void {
			echo '<table class="widefat striped" style="max-width: 900px"><thead><tr>';
			echo '<th>' . esc_html__('Module', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('State', 'wp-security-toolkit') . '</th>';
			echo '<th>' . esc_html__('Source', 'wp-security-toolkit') . '</th>';
			echo '</tr></thead><tbody>';

			foreach ($modules as $slug => $data) {
				$state = is_array($data) && isset($data['state']) ? (string) $data['state'] : 'unknown';
				$source = is_array($data) && isset($data['source']) ? (string) $data['source'] : 'unknown';
				echo '<tr>';
				echo '<td><code>' . esc_html((string) $slug) . '</code></td>';
				echo '<td>' . esc_html($state) . '</td>';
				echo '<td>' . esc_html($source) . '</td>';
				echo '</tr>';
			}

			echo '</tbody></table>';
		}

		private function extract_host(string $url): string {
			$host = wp_parse_url($url, PHP_URL_HOST);
			return is_string($host) && '' !== $host ? $host : 'unknown';
		}

		private function constant_state(string $constant_name): string {
			if (! defined($constant_name)) {
				return 'undefined';
			}

			return constant($constant_name) ? 'true' : 'false';
		}

	}
}

$bootstrap = static function (): void {
	$dashboard = new WPST_Diagnostics_Dashboard();
	$dashboard->register_hooks();
};

if (did_action('muplugins_loaded')) {
	$bootstrap();
} else {
	add_action('plugins_loaded', $bootstrap);
}
