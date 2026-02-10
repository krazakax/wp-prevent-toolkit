<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

/**
 * WP Security Toolkit: Request rate limiting and adaptive blocking.
 *
 * Filters:
 * - wpst_rate_limiter_enabled (bool)
 * - wpst_rate_limiter_trusted_proxies (array<int, string> CIDR/IP list)
 * - wpst_rate_limiter_whitelist (array<int, string> CIDR/IP list)
 * - wpst_rate_limiter_google_bypass (bool)
 * - wpst_rate_limiter_admin_bypass (bool)
 * - wpst_rate_limiter_response_code_block (int)
 * - wpst_rate_limiter_block_message (string)
 */
if (! class_exists('WPST_Rate_Limiter')) {
	final class WPST_Rate_Limiter {
		private const OPTION_KEY = 'wpst_rate_limiter_settings';
		private const SETTINGS_GROUP = 'wpst_rate_limiter_settings_group';
		private const PAGE_SLUG = 'wpst-rate-limiting';
		private const CACHE_GROUP = 'wpst_rate_limiter';

		/**
		 * @var array<string, mixed>|null
		 */
		private ?array $settings_cache = null;

		/**
		 * @var string|null
		 */
		private ?string $client_ip_cache = null;

		public function register_hooks(): void {
			add_action('admin_menu', [$this, 'register_admin_menu']);
			add_action('admin_init', [$this, 'register_settings']);
			add_action('parse_request', [$this, 'enforce_early_block'], 1);
			add_action('template_redirect', [$this, 'evaluate_request_rate'], 1);
			add_filter('wpst_rate_limiter_debug_snapshot', [$this, 'filter_debug_snapshot']);
		}

		/**
		 * @param mixed $snapshot
		 * @return mixed
		 */
		public function filter_debug_snapshot($snapshot) {
			if (! $this->is_debug_snapshot_available()) {
				return $snapshot;
			}

			return $this->build_debug_snapshot();
		}

		public function register_admin_menu(): void {
			add_submenu_page(
				'wp-security-toolkit',
				__('WP Security Toolkit — Rate Limiting', 'wp-security-toolkit'),
				__('Rate Limiting', 'wp-security-toolkit'),
				'manage_options',
				self::PAGE_SLUG,
				[$this, 'render_settings_page']
			);
		}

		public function register_settings(): void {
			register_setting(
				self::SETTINGS_GROUP,
				self::OPTION_KEY,
				[
					'type' => 'array',
					'sanitize_callback' => [$this, 'sanitize_settings'],
					'default' => $this->default_settings(),
				]
			);

			add_settings_section(
				'wpst_rate_limiter_main',
				__('Rate Limiting Rules', 'wp-security-toolkit'),
				'__return_null',
				self::PAGE_SLUG
			);

			$this->add_checkbox_field('enabled', __('Enable rate limiting', 'wp-security-toolkit'));
			$this->add_checkbox_field('google_verified_bypass', __('Bypass verified Google crawlers', 'wp-security-toolkit'));
			$this->add_rule_fields('any_requests_per_min', 'any_action', __('Any requests per minute', 'wp-security-toolkit'));
			$this->add_rule_fields('human_views_per_min', 'human_views_action', __('Human page views per minute', 'wp-security-toolkit'));
			$this->add_rule_fields('human_404_per_min', 'human_404_action', __('Human 404 responses per minute', 'wp-security-toolkit'));
			$this->add_rule_fields('crawler_views_per_min', 'crawler_views_action', __('Crawler page views per minute', 'wp-security-toolkit'));
			$this->add_rule_fields('crawler_404_per_min', 'crawler_404_action', __('Crawler 404 responses per minute', 'wp-security-toolkit'));

			add_settings_field(
				'block_duration_seconds',
				__('Block duration', 'wp-security-toolkit'),
				[$this, 'render_block_duration_field'],
				self::PAGE_SLUG,
				'wpst_rate_limiter_main'
			);

			$this->add_textarea_field('whitelist_ips', __('Whitelist IPs/CIDRs (one per line)', 'wp-security-toolkit'));
			$this->add_textarea_field('trusted_proxies', __('Trusted proxies (one per line, CIDR/IP)', 'wp-security-toolkit'));
		}

		public function render_settings_page(): void {
			if (! current_user_can('manage_options')) {
				return;
			}
			?>
			<div class="wrap">
				<h1><?php echo esc_html__('WP Security Toolkit — Rate Limiting', 'wp-security-toolkit'); ?></h1>
				<form method="post" action="options.php">
					<?php settings_fields(self::SETTINGS_GROUP); ?>
					<?php do_settings_sections(self::PAGE_SLUG); ?>
					<?php submit_button(); ?>
				</form>
			</div>
			<?php
		}

		/**
		 * @param mixed $input
		 * @return array<string, mixed>
		 */
		public function sanitize_settings($input): array {
			$defaults = $this->default_settings();
			$input = is_array($input) ? $input : [];

			$sanitized = $defaults;
			$sanitized['enabled'] = ! empty($input['enabled']);
			$sanitized['google_verified_bypass'] = ! empty($input['google_verified_bypass']);

			$int_fields = [
				'any_requests_per_min',
				'crawler_views_per_min',
				'crawler_404_per_min',
				'human_views_per_min',
				'human_404_per_min',
				'block_duration_seconds',
			];

			foreach ($int_fields as $field) {
				$sanitized[$field] = isset($input[$field]) ? max(0, (int) $input[$field]) : (int) $defaults[$field];
			}

			$action_fields = [
				'any_action',
				'crawler_views_action',
				'crawler_404_action',
				'human_views_action',
				'human_404_action',
			];

			foreach ($action_fields as $field) {
				$action = isset($input[$field]) ? (string) $input[$field] : (string) $defaults[$field];
				$sanitized[$field] = in_array($action, ['throttle', 'block'], true) ? $action : 'block';
			}

			$sanitized['whitelist_ips'] = $this->sanitize_cidr_multiline((string) ($input['whitelist_ips'] ?? ''));
			$sanitized['trusted_proxies'] = $this->sanitize_cidr_multiline((string) ($input['trusted_proxies'] ?? ''));

			$this->settings_cache = $sanitized;
			return $sanitized;
		}

		public function enforce_early_block(): void {
			if (! $this->is_enforcement_applicable()) {
				return;
			}

			$ip = $this->get_client_ip();
			if ('' === $ip) {
				return;
			}

			if ($this->is_whitelisted_ip($ip)) {
				return;
			}

			if ($this->is_blocked($ip)) {
				$this->send_block_response();
			}
		}

		public function evaluate_request_rate(): void {
			if (! $this->is_enforcement_applicable()) {
				return;
			}

			$ip = $this->get_client_ip();
			if ('' === $ip || $this->is_whitelisted_ip($ip)) {
				return;
			}

			if ($this->is_google_verified_bypass($ip)) {
				return;
			}

			$is_404 = is_404();
			$is_crawler = $this->is_crawler_request();
			$minute_bucket = gmdate('YmdHi');
			$max_sleep_seconds = 0;

			$rules = [
				[
					'type' => 'any',
					'limit_key' => 'any_requests_per_min',
					'action_key' => 'any_action',
				],
			];

			if ($is_crawler) {
				$rules[] = [
					'type' => $is_404 ? 'crawler_404' : 'crawler_view',
					'limit_key' => $is_404 ? 'crawler_404_per_min' : 'crawler_views_per_min',
					'action_key' => $is_404 ? 'crawler_404_action' : 'crawler_views_action',
				];
			} else {
				$rules[] = [
					'type' => $is_404 ? 'human_404' : 'human_view',
					'limit_key' => $is_404 ? 'human_404_per_min' : 'human_views_per_min',
					'action_key' => $is_404 ? 'human_404_action' : 'human_views_action',
				];
			}

			foreach ($rules as $rule) {
				$count = $this->increment_counter((string) $rule['type'], $ip, $minute_bucket);
				$limit = (int) $this->settings()[(string) $rule['limit_key']];
				if ($limit <= 0 || $count <= $limit) {
					continue;
				}

				$action = (string) $this->settings()[(string) $rule['action_key']];
				if ('block' === $action) {
					$this->block_ip($ip);
					$this->send_block_response();
				}

				$max_sleep_seconds = max($max_sleep_seconds, $this->calculate_throttle_seconds($count, $limit));
			}

			if ($max_sleep_seconds > 0) {
				sleep($max_sleep_seconds);
			}
		}

		private function add_checkbox_field(string $field, string $label): void {
			add_settings_field(
				$field,
				$label,
				function () use ($field): void {
					$value = ! empty($this->settings()[$field]);
					printf(
						'<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s /></label>',
						esc_attr(self::OPTION_KEY),
						esc_attr($field),
						checked($value, true, false)
					);
				},
				self::PAGE_SLUG,
				'wpst_rate_limiter_main'
			);
		}

		private function add_textarea_field(string $field, string $label): void {
			add_settings_field(
				$field,
				$label,
				function () use ($field): void {
					$value = (string) ($this->settings()[$field] ?? '');
					printf(
						'<textarea name="%1$s[%2$s]" rows="6" cols="60" class="large-text code">%3$s</textarea>',
						esc_attr(self::OPTION_KEY),
						esc_attr($field),
						esc_textarea($value)
					);
				},
				self::PAGE_SLUG,
				'wpst_rate_limiter_main'
			);
		}

		private function add_rule_fields(string $limit_field, string $action_field, string $label): void {
			add_settings_field(
				$limit_field,
				$label,
				function () use ($limit_field, $action_field): void {
					$limit = (int) ($this->settings()[$limit_field] ?? 0);
					$action = (string) ($this->settings()[$action_field] ?? 'block');
					printf(
						'<input type="number" min="0" step="1" name="%1$s[%2$s]" value="%3$d" class="small-text" />',
						esc_attr(self::OPTION_KEY),
						esc_attr($limit_field),
						$limit
					);
					echo '&nbsp;';
					printf(
						'<select name="%1$s[%2$s]"><option value="throttle" %3$s>%4$s</option><option value="block" %5$s>%6$s</option></select>',
						esc_attr(self::OPTION_KEY),
						esc_attr($action_field),
						selected($action, 'throttle', false),
						esc_html__('Throttle', 'wp-security-toolkit'),
						selected($action, 'block', false),
						esc_html__('Block', 'wp-security-toolkit')
					);
				},
				self::PAGE_SLUG,
				'wpst_rate_limiter_main'
			);
		}

		public function render_block_duration_field(): void {
			$current = (int) ($this->settings()['block_duration_seconds'] ?? 432000);
			$options = [
				3600 => __('1 hour', 'wp-security-toolkit'),
				86400 => __('24 hours', 'wp-security-toolkit'),
				432000 => __('5 days (default)', 'wp-security-toolkit'),
				604800 => __('7 days', 'wp-security-toolkit'),
				2592000 => __('30 days', 'wp-security-toolkit'),
			];

			printf('<select name="%1$s[block_duration_seconds]">', esc_attr(self::OPTION_KEY));
			foreach ($options as $seconds => $label) {
				printf(
					'<option value="%1$d" %2$s>%3$s</option>',
					(int) $seconds,
					selected($current, (int) $seconds, false),
					esc_html($label)
				);
			}
			echo '</select>';
		}

		/**
		 * @return array<string, mixed>
		 */
		private function settings(): array {
			if (null !== $this->settings_cache) {
				return $this->settings_cache;
			}

			$settings = get_option(self::OPTION_KEY, []);
			if (! is_array($settings)) {
				$settings = [];
			}

			$this->settings_cache = array_merge($this->default_settings(), $settings);
			return $this->settings_cache;
		}

		/**
		 * @return array<string, mixed>
		 */
		private function default_settings(): array {
			return [
				'enabled' => false,
				'google_verified_bypass' => true,
				'any_requests_per_min' => 300,
				'any_action' => 'throttle',
				'crawler_views_per_min' => 180,
				'crawler_views_action' => 'throttle',
				'crawler_404_per_min' => 60,
				'crawler_404_action' => 'block',
				'human_views_per_min' => 120,
				'human_views_action' => 'throttle',
				'human_404_per_min' => 30,
				'human_404_action' => 'block',
				'block_duration_seconds' => 432000,
				'whitelist_ips' => '',
				'trusted_proxies' => '',
			];
		}

		private function is_enforcement_applicable(): bool {
			$enabled = (bool) apply_filters('wpst_rate_limiter_enabled', (bool) $this->settings()['enabled']);
			if (! $enabled) {
				return false;
			}

			$admin_bypass = (bool) apply_filters('wpst_rate_limiter_admin_bypass', true);
			if ($admin_bypass && (is_admin() || (is_user_logged_in() && current_user_can('manage_options')))) {
				return false;
			}

			return true;
		}

		private function is_debug_snapshot_available(): bool {
			if (! is_admin() || ! current_user_can('manage_options')) {
				return false;
			}

			return (bool) apply_filters('wpst_rate_limiter_debug_enabled', false);
		}

		/**
		 * @return array<string, mixed>
		 */
		private function build_debug_snapshot(): array {
			$ip = $this->get_client_ip();
			$minute_bucket = gmdate('YmdHi');
			$user_agent_bucket = $this->is_crawler_request() ? 'crawler' : 'human';
			$settings = $this->settings();

			$block_key = '';
			$is_whitelisted = false;
			$is_blocked = false;
			$block_ttl = null;

			if ('' !== $ip) {
				$is_whitelisted = $this->is_whitelisted_ip($ip);
				$block_key = $this->get_block_key($ip);
				$is_blocked = $this->is_blocked($ip);
				if ($is_blocked) {
					$block_ttl = $this->get_transient_ttl_seconds($block_key);
				}
			}

			$counters = [];
			foreach (['any', 'human_view', 'human_404', 'crawler_view', 'crawler_404'] as $type) {
				$key = '' !== $ip ? $this->get_counter_key($type, $ip, $minute_bucket) : '';
				$value = '' !== $key ? $this->read_counter($key) : 0;
				$counters[$type] = [
					'transient_key' => $key,
					'value' => $value,
					'ttl_seconds' => '' !== $key ? $this->get_transient_ttl_seconds($key) : null,
				];
			}

			return [
				'detected_ip' => $ip,
				'is_admin_bypassed' => $this->is_admin_bypass_enabled_for_request(),
				'is_whitelisted' => $is_whitelisted,
				'is_blocked' => $is_blocked,
				'block_transient_key' => $block_key,
				'block_expires_in_seconds' => $block_ttl,
				'current_minute_bucket' => $minute_bucket,
				'user_agent_bucket' => $user_agent_bucket,
				'counters' => $counters,
				'settings_summary' => [
					'thresholds' => [
						'any_requests_per_min' => (int) ($settings['any_requests_per_min'] ?? 0),
						'human_views_per_min' => (int) ($settings['human_views_per_min'] ?? 0),
						'human_404_per_min' => (int) ($settings['human_404_per_min'] ?? 0),
						'crawler_views_per_min' => (int) ($settings['crawler_views_per_min'] ?? 0),
						'crawler_404_per_min' => (int) ($settings['crawler_404_per_min'] ?? 0),
					],
					'actions' => [
						'any' => (string) ($settings['any_action'] ?? 'throttle'),
						'human_view' => (string) ($settings['human_views_action'] ?? 'throttle'),
						'human_404' => (string) ($settings['human_404_action'] ?? 'block'),
						'crawler_view' => (string) ($settings['crawler_views_action'] ?? 'throttle'),
						'crawler_404' => (string) ($settings['crawler_404_action'] ?? 'block'),
					],
					'block_duration_seconds' => (int) ($settings['block_duration_seconds'] ?? 0),
				],
			];
		}

		private function is_admin_bypass_enabled_for_request(): bool {
			$admin_bypass = (bool) apply_filters('wpst_rate_limiter_admin_bypass', true);
			if (! $admin_bypass) {
				return false;
			}

			return is_admin() || (is_user_logged_in() && current_user_can('manage_options'));
		}

		private function is_blocked(string $ip): bool {
			$key = $this->get_block_key($ip);

			if (wp_using_ext_object_cache()) {
				$blocked = wp_cache_get($key, self::CACHE_GROUP);
				if (false !== $blocked) {
					return (bool) $blocked;
				}
			}

			return (bool) get_transient($key);
		}

		private function block_ip(string $ip): void {
			$key = $this->get_block_key($ip);
			$duration = max(60, (int) $this->settings()['block_duration_seconds']);

			if (wp_using_ext_object_cache()) {
				wp_cache_set($key, 1, self::CACHE_GROUP, $duration);
			}

			set_transient($key, 1, $duration);
		}

		private function send_block_response(): void {
			$status = (int) apply_filters('wpst_rate_limiter_response_code_block', 429);
			if ($status < 400 || $status > 599) {
				$status = 429;
			}

			nocache_headers();
			status_header($status);
			if (429 === $status) {
				header('Retry-After: ' . (string) max(60, (int) $this->settings()['block_duration_seconds']));
			}

			$message = (string) apply_filters('wpst_rate_limiter_block_message', __('Too many requests. Please try again later.', 'wp-security-toolkit'));
			wp_die(esc_html($message), esc_html__('Request temporarily limited', 'wp-security-toolkit'), ['response' => $status]);
		}

		private function calculate_throttle_seconds(int $count, int $limit): int {
			$overage = max(1, $count - $limit);
			$step = max(1, (int) floor($limit / 2));
			return min(3, 1 + (int) floor($overage / $step));
		}

		private function increment_counter(string $type, string $ip, string $minute_bucket): int {
			$key = $this->get_counter_key($type, $ip, $minute_bucket);
			$count = $this->read_counter($key) + 1;
			$this->write_counter($key, $count, 120);
			return $count;
		}

		private function read_counter(string $key): int {
			if (wp_using_ext_object_cache()) {
				$cached = wp_cache_get($key, self::CACHE_GROUP);
				if (false !== $cached) {
					return max(0, (int) $cached);
				}
			}

			return max(0, (int) get_transient($key));
		}

		private function write_counter(string $key, int $value, int $ttl): void {
			if (wp_using_ext_object_cache()) {
				wp_cache_set($key, $value, self::CACHE_GROUP, $ttl);
			}

			set_transient($key, $value, $ttl);
		}

		private function get_transient_ttl_seconds(string $key): ?int {
			if (wp_using_ext_object_cache()) {
				return null;
			}

			$timeout = get_option('_transient_timeout_' . $key);
			if (! is_numeric($timeout)) {
				return null;
			}

			$remaining = (int) $timeout - time();
			return $remaining > 0 ? $remaining : 0;
		}

		private function is_crawler_request(): bool {
			$ua = strtolower((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
			if ('' === $ua) {
				return false;
			}

			$keywords = ['bot', 'crawler', 'spider', 'slurp', 'bingpreview', 'duckduckbot', 'baiduspider', 'yandex'];
			foreach ($keywords as $keyword) {
				if (str_contains($ua, $keyword)) {
					return true;
				}
			}

			return false;
		}

		private function is_google_verified_bypass(string $ip): bool {
			$enabled = (bool) apply_filters('wpst_rate_limiter_google_bypass', (bool) $this->settings()['google_verified_bypass']);
			if (! $enabled) {
				return false;
			}

			$ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
			if ('' === $ua || ! str_contains($ua, 'Googlebot')) {
				return false;
			}

			$cache_key = 'wpst_rl_google_verify_' . md5($ip);
			$cached = get_transient($cache_key);
			if (false !== $cached) {
				return '1' === (string) $cached;
			}

			$verified = $this->verify_google_crawler_ip($ip);
			set_transient($cache_key, $verified ? '1' : '0', DAY_IN_SECONDS);
			return $verified;
		}

		private function verify_google_crawler_ip(string $ip): bool {
			$hostname = gethostbyaddr($ip);
			if (! is_string($hostname) || '' === $hostname || $hostname === $ip) {
				return false;
			}

			$normalized = strtolower(rtrim($hostname, '.'));
			if (! str_ends_with($normalized, '.googlebot.com') && ! str_ends_with($normalized, '.google.com')) {
				return false;
			}

			$records = dns_get_record($hostname, DNS_A + DNS_AAAA);
			if (! is_array($records) || [] === $records) {
				return false;
			}

			foreach ($records as $record) {
				if (! is_array($record)) {
					continue;
				}

				$resolved_ip = '';
				if (isset($record['ip']) && is_string($record['ip'])) {
					$resolved_ip = $record['ip'];
				}
				if (isset($record['ipv6']) && is_string($record['ipv6'])) {
					$resolved_ip = $record['ipv6'];
				}

				if ($resolved_ip === $ip) {
					return true;
				}
			}

			return false;
		}

		private function get_counter_key(string $type, string $ip, string $minute_bucket): string {
			return 'wpst_rl:' . $type . ':' . md5($ip) . ':' . $minute_bucket;
		}

		private function get_block_key(string $ip): string {
			return 'wpst_rl_block:' . md5($ip);
		}

		private function is_whitelisted_ip(string $ip): bool {
			$whitelist = $this->parse_cidr_lines((string) ($this->settings()['whitelist_ips'] ?? ''));
			$whitelist = apply_filters('wpst_rate_limiter_whitelist', $whitelist);
			if (! is_array($whitelist)) {
				$whitelist = [];
			}

			return $this->ip_matches_any_cidr($ip, $whitelist);
		}

		private function get_client_ip(): string {
			if (null !== $this->client_ip_cache) {
				return $this->client_ip_cache;
			}

			$remote_addr = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
			if (! $this->is_valid_ip($remote_addr)) {
				$this->client_ip_cache = '';
				return $this->client_ip_cache;
			}

			$trusted = $this->parse_cidr_lines((string) ($this->settings()['trusted_proxies'] ?? ''));
			$trusted = apply_filters('wpst_rate_limiter_trusted_proxies', $trusted);
			if (! is_array($trusted)) {
				$trusted = [];
			}

			if ($this->ip_matches_any_cidr($remote_addr, $trusted)) {
				$xff = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
				if ('' !== $xff) {
					$parts = explode(',', $xff);
					foreach ($parts as $part) {
						$candidate = trim($part);
						if ($this->is_valid_ip($candidate)) {
							$this->client_ip_cache = $candidate;
							return $this->client_ip_cache;
						}
					}
				}
			}

			$this->client_ip_cache = $remote_addr;
			return $this->client_ip_cache;
		}

		/**
		 * @param array<int, mixed> $cidrs
		 */
		private function ip_matches_any_cidr(string $ip, array $cidrs): bool {
			foreach ($cidrs as $cidr) {
				if (! is_scalar($cidr)) {
					continue;
				}
				if ($this->ip_matches_cidr($ip, (string) $cidr)) {
					return true;
				}
			}

			return false;
		}

		private function ip_matches_cidr(string $ip, string $cidr): bool {
			$cidr = trim($cidr);
			if ('' === $cidr) {
				return false;
			}

			if (! str_contains($cidr, '/')) {
				return $ip === $cidr;
			}

			[$subnet, $bits_raw] = explode('/', $cidr, 2);
			$subnet = trim($subnet);
			$bits = (int) $bits_raw;

			$ip_bin = @inet_pton($ip);
			$subnet_bin = @inet_pton($subnet);
			if (false === $ip_bin || false === $subnet_bin) {
				return false;
			}

			if (strlen($ip_bin) !== strlen($subnet_bin)) {
				return false;
			}

			$max_bits = 8 * strlen($ip_bin);
			if ($bits < 0 || $bits > $max_bits) {
				return false;
			}

			$full_bytes = intdiv($bits, 8);
			$remaining_bits = $bits % 8;

			if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
				return false;
			}

			if (0 === $remaining_bits) {
				return true;
			}

			$mask = (~((1 << (8 - $remaining_bits)) - 1)) & 0xFF;
			$ip_byte = ord($ip_bin[$full_bytes]);
			$subnet_byte = ord($subnet_bin[$full_bytes]);

			return ($ip_byte & $mask) === ($subnet_byte & $mask);
		}

		private function is_valid_ip(string $ip): bool {
			return false !== filter_var($ip, FILTER_VALIDATE_IP);
		}


		private function is_valid_ip_or_cidr(string $value): bool {
			if ($this->is_valid_ip($value)) {
				return true;
			}

			if (! str_contains($value, '/')) {
				return false;
			}

			[$subnet, $bits_raw] = explode('/', $value, 2);
			$subnet = trim($subnet);
			if (! $this->is_valid_ip($subnet)) {
				return false;
			}

			if ($bits_raw === '' || ! ctype_digit($bits_raw)) {
				return false;
			}

			$bits = (int) $bits_raw;
			$subnet_bin = @inet_pton($subnet);
			if (false === $subnet_bin) {
				return false;
			}

			$max_bits = 8 * strlen($subnet_bin);
			return $bits >= 0 && $bits <= $max_bits;
		}

		private function sanitize_cidr_multiline(string $value): string {
			$lines = $this->parse_cidr_lines($value);
			return implode("\n", $lines);
		}

		/**
		 * @return array<int, string>
		 */
		private function parse_cidr_lines(string $value): array {
			$lines = preg_split('/\r\n|\r|\n/', $value) ?: [];
			$clean = [];
			foreach ($lines as $line) {
				$line = trim((string) $line);
				if ('' === $line) {
					continue;
				}

				if ($this->is_valid_ip_or_cidr($line)) {
					$clean[] = $line;
				}
			}

			return array_values(array_unique($clean));
		}
	}

	$wpst_rate_limiter = new WPST_Rate_Limiter();
	$wpst_rate_limiter->register_hooks();
}
