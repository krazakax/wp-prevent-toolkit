<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Rate_Limiter_Events')) {
	final class WPST_Rate_Limiter_Events {
		public const TABLE_SUFFIX = 'wpst_rate_limit_events';
		public const DB_VERSION_OPTION = 'wpst_db_version';
		public const DB_VERSION = '2';
		public const CLEANUP_HOOK = 'wpst_rate_limit_events_cleanup_daily';

		public static function register_hooks(): void {
			add_action(self::CLEANUP_HOOK, [self::class, 'cleanup_expired_events']);
		}

		public static function activate(): void {
			self::install_or_upgrade_table();
			self::ensure_cleanup_schedule();
		}

		public static function install_or_upgrade_table(): void {
			global $wpdb;
			if (! isset($wpdb) || ! ($wpdb instanceof wpdb)) {
				return;
			}

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';

			$charset_collate = $wpdb->get_charset_collate();
			$table_name = self::table_name();

			$sql = "CREATE TABLE {$table_name} (
				id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
				created_at_utc DATETIME NOT NULL,
				ip_hash CHAR(64) NOT NULL,
				ip_raw VARBINARY(16) NULL,
				country CHAR(2) NULL,
				action VARCHAR(16) NOT NULL,
				rule VARCHAR(32) NOT NULL,
				bucket VARCHAR(16) NOT NULL,
				path VARCHAR(255) NOT NULL,
				user_agent VARCHAR(255) NOT NULL,
				duration_seconds INT(10) UNSIGNED NULL,
				PRIMARY KEY  (id),
				KEY created_at_utc (created_at_utc),
				KEY ip_hash (ip_hash),
				KEY action (action)
			) {$charset_collate};";

			dbDelta($sql);
			update_option(self::DB_VERSION_OPTION, self::DB_VERSION, false);
		}

		public static function ensure_cleanup_schedule(): void {
			if (! wp_next_scheduled(self::CLEANUP_HOOK)) {
				wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK);
			}
		}

		public static function cleanup_expired_events(): void {
			global $wpdb;
			if (! isset($wpdb) || ! ($wpdb instanceof wpdb)) {
				return;
			}

			$retention_days = (int) apply_filters('wpst_rate_limit_event_retention_days', 14);
			$retention_days = max(1, $retention_days);
			$cutoff = gmdate('Y-m-d H:i:s', time() - ($retention_days * DAY_IN_SECONDS));

			$table_name = self::table_name();
			$wpdb->query($wpdb->prepare("DELETE FROM {$table_name} WHERE created_at_utc < %s", $cutoff));
		}

		/**
		 * @param array<string, mixed> $data
		 */
		public static function log_event(array $data): void {
			global $wpdb;
			if (! isset($wpdb) || ! ($wpdb instanceof wpdb)) {
				return;
			}

			$ip = isset($data['detected_ip']) ? (string) $data['detected_ip'] : '';
			if ('' === $ip || false === filter_var($ip, FILTER_VALIDATE_IP)) {
				return;
			}

			$action = isset($data['action']) ? sanitize_key((string) $data['action']) : '';
			$rule = isset($data['rule']) ? sanitize_key((string) $data['rule']) : '';
			$bucket = isset($data['bucket']) ? sanitize_key((string) $data['bucket']) : '';

			if (! in_array($action, ['throttle', 'block'], true)) {
				return;
			}

			$allowed_rules = ['any', 'human_views', 'human_404', 'crawler_views', 'crawler_404'];
			if (! in_array($rule, $allowed_rules, true)) {
				$rule = 'any';
			}

			if (! in_array($bucket, ['human', 'crawler'], true)) {
				$bucket = 'human';
			}

			$user_agent = isset($data['user_agent']) ? sanitize_text_field((string) $data['user_agent']) : '';
			$user_agent = mb_substr($user_agent, 0, 255);

			$path = isset($data['path']) ? (string) $data['path'] : self::request_path();
			$path = wp_parse_url($path, PHP_URL_PATH);
			$path = is_string($path) ? $path : '';
			$path = sanitize_text_field($path);
			$path = mb_substr($path, 0, 255);
			if ('' === $path) {
				$path = '/';
			}

			$raw_country = $data['country'] ?? self::detect_country_code();
			$country = is_string($raw_country) ? self::normalize_country_code($raw_country) : null;

			$duration_seconds = isset($data['duration_seconds']) && null !== $data['duration_seconds'] ? max(0, (int) $data['duration_seconds']) : null;

			$ip_hash = hash_hmac('sha256', $ip, wp_salt('auth'));
			$store_raw_ip = (bool) apply_filters('wpst_log_raw_ip', false);
			$ip_raw = null;
			if ($store_raw_ip) {
				$packed = @inet_pton($ip);
				$ip_raw = false !== $packed ? $packed : null;
			}

			$wpdb->insert(
				self::table_name(),
				[
					'created_at_utc' => gmdate('Y-m-d H:i:s'),
					'ip_hash' => $ip_hash,
					'ip_raw' => $ip_raw,
					'country' => $country,
					'action' => $action,
					'rule' => $rule,
					'bucket' => $bucket,
					'path' => $path,
					'user_agent' => $user_agent,
					'duration_seconds' => $duration_seconds,
				],
				[
					'%s',
					'%s',
					'%s',
					'%s',
					'%s',
					'%s',
					'%s',
					'%s',
					'%s',
					'%d',
				]
			);
		}

		/**
		 * @return array<int, array<string, mixed>>
		 */
		public static function recent_events(int $limit = 50): array {
			global $wpdb;
			if (! isset($wpdb) || ! ($wpdb instanceof wpdb)) {
				return [];
			}

			$limit = max(1, min(200, $limit));
			$table_name = self::table_name();
			$query = $wpdb->prepare(
				"SELECT created_at_utc, action, rule, bucket, country, ip_hash, path, user_agent FROM {$table_name} ORDER BY id DESC LIMIT %d",
				$limit
			);

			$rows = $wpdb->get_results($query, ARRAY_A);
			if (! is_array($rows)) {
				return [];
			}

			$events = [];
			foreach ($rows as $row) {
				if (! is_array($row)) {
					continue;
				}
				$events[] = [
					'created_at_utc' => (string) ($row['created_at_utc'] ?? ''),
					'action' => (string) ($row['action'] ?? ''),
					'rule' => (string) ($row['rule'] ?? ''),
					'bucket' => (string) ($row['bucket'] ?? ''),
					'country' => (string) ($row['country'] ?? ''),
					'ip_hash' => (string) ($row['ip_hash'] ?? ''),
					'path' => (string) ($row['path'] ?? ''),
					'user_agent' => (string) ($row['user_agent'] ?? ''),
				];
			}

			return $events;
		}

		public static function detect_country_code(): ?string {
			$cf_country = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? (string) $_SERVER['HTTP_CF_IPCOUNTRY'] : '';
			$country = self::normalize_country_code($cf_country);
			if (null !== $country) {
				return $country;
			}

			$x_country = isset($_SERVER['HTTP_X_COUNTRY_CODE']) ? (string) $_SERVER['HTTP_X_COUNTRY_CODE'] : '';
			return self::normalize_country_code($x_country);
		}

		private static function normalize_country_code(?string $country): ?string {
			if (null === $country) {
				return null;
			}

			$country = strtoupper(trim($country));
			if (preg_match('/^[A-Z]{2}$/', $country) !== 1) {
				return null;
			}

			return $country;
		}

		private static function request_path(): string {
			$request_uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
			$path = wp_parse_url($request_uri, PHP_URL_PATH);
			if (! is_string($path) || '' === $path) {
				return '/';
			}

			return $path;
		}

		private static function table_name(): string {
			global $wpdb;
			return isset($wpdb) && ($wpdb instanceof wpdb) ? $wpdb->prefix . self::TABLE_SUFFIX : '';
		}
	}
}

if (! function_exists('wpst_log_rate_limit_event')) {
	/**
	 * @param array<string, mixed> $data
	 */
	function wpst_log_rate_limit_event(array $data): void {
		WPST_Rate_Limiter_Events::log_event($data);
	}
}

WPST_Rate_Limiter_Events::register_hooks();
