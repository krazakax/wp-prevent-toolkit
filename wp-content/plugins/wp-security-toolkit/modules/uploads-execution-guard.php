<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Uploads_Execution_Guard')) {
	final class WPST_Uploads_Execution_Guard {
		private const SCAN_INTERVAL = DAY_IN_SECONDS;
		private const SCAN_MAX_FILES = 20000;
		private const SCAN_MAX_DEPTH = 10;
		private const SCAN_MAX_RESULTS = 20;

		private const SCAN_RESULTS_OPTION = 'wpst_uploads_scan_results';
		private const SCAN_LAST_RUN_TRANSIENT = 'wpst_uploads_scan_last_run';
		private const NGINX_NOTICE_TRANSIENT = 'wpst_uploads_nginx_notice';

		private bool $initialized = false;

		public function init(): void {
			if ($this->initialized) {
				return;
			}

			$this->initialized = true;

			add_filter('upload_mimes', [$this, 'filter_upload_mimes']);
			add_filter('wp_check_filetype_and_ext', [$this, 'enforce_blocked_extensions'], 10, 5);
			add_action('admin_init', [$this, 'on_admin_init']);
			add_action('admin_notices', [$this, 'render_admin_notices']);
		}

		/**
		 * Remove dangerous extensions from allowed upload mimes.
		 *
		 * @param array<string, string> $mimes
		 * @return array<string, string>
		 */
		public function filter_upload_mimes(array $mimes): array {
			$blocked_extensions = $this->get_blocked_extensions();

			foreach (array_keys($mimes) as $extensions) {
				$parts = preg_split('/\|/', strtolower((string) $extensions));

				if (! is_array($parts)) {
					continue;
				}

				foreach ($parts as $part) {
					if (in_array($part, $blocked_extensions, true)) {
						unset($mimes[$extensions]);
						break;
					}
				}
			}

			if ($this->should_block_svg()) {
				foreach (array_keys($mimes) as $extensions) {
					$parts = preg_split('/\|/', strtolower((string) $extensions));
					if (is_array($parts) && in_array('svg', $parts, true)) {
						unset($mimes[$extensions]);
					}
				}
			}

			return $mimes;
		}

		/**
		 * Enforce extension blocking even if mime map checks are bypassed.
		 *
		 * @param array<string, mixed> $data
		 * @param string               $file
		 * @param string               $filename
		 * @param array<string, string>|null $mimes
		 * @param string|false         $real_mime
		 * @return array<string, mixed>
		 */
		public function enforce_blocked_extensions(array $data, string $file, string $filename, ?array $mimes, $real_mime): array {
			$basename = wp_basename($filename);
			$lower_name = strtolower($basename);
			$blocked_extensions = $this->get_blocked_extensions();
			$parts = explode('.', $lower_name);
			$final_extension = count($parts) > 1 ? (string) end($parts) : '';

			$is_blocked = false;
			if ('' !== $final_extension && in_array($final_extension, $blocked_extensions, true)) {
				$is_blocked = true;
			}

			if (! $is_blocked && $this->should_block_svg() && 'svg' === $final_extension) {
				$is_blocked = true;
			}

			if (! $is_blocked && count($parts) > 2) {
				foreach ($parts as $index => $extension) {
					if (0 === $index || count($parts) - 1 === $index) {
						continue;
					}

					if (in_array($extension, $blocked_extensions, true)) {
						$is_blocked = true;
						break;
					}

					if ($this->should_block_svg() && 'svg' === $extension) {
						$is_blocked = true;
						break;
					}
				}
			}

			if (! $is_blocked) {
				return $data;
			}

			$data['ext'] = false;
			$data['type'] = false;
			$data['proper_filename'] = false;
			$data['error'] = __('This file type is blocked by WP Security Toolkit Uploads Guard.', 'wp-security-toolkit');

			return $data;
		}

		public function on_admin_init(): void {
			if (! is_admin() || ! current_user_can('manage_options')) {
				return;
			}

			if ((bool) apply_filters('wpst_uploads_scan_enabled', true)) {
				$this->maybe_scan_uploads_directory();
			}

			if ((bool) apply_filters('wpst_uploads_auto_write_htaccess', false)) {
				$this->maybe_write_htaccess_guard();
			}
		}

		public function render_admin_notices(): void {
			if (! is_admin() || ! current_user_can('manage_options')) {
				return;
			}

			if (! (bool) apply_filters('wpst_uploads_notice_enabled', true)) {
				return;
			}

			$results = get_option(self::SCAN_RESULTS_OPTION);
			if (is_array($results) && ! empty($results['files']) && is_array($results['files'])) {
				$files = array_slice(array_map('strval', $results['files']), 0, self::SCAN_MAX_RESULTS);
				$last_scan = isset($results['last_scan']) ? (int) $results['last_scan'] : 0;
				$last_scan_text = $last_scan > 0 ? gmdate('Y-m-d H:i:s', $last_scan) . ' UTC' : __('unknown time', 'wp-security-toolkit');

				echo '<div class="notice notice-warning"><p><strong>' . esc_html__('WP Security Toolkit:', 'wp-security-toolkit') . '</strong> ';
				echo esc_html__('Potential executable files were found in uploads. Review and remove anything suspicious.', 'wp-security-toolkit');
				echo ' ' . esc_html(sprintf(__('Last scan: %s.', 'wp-security-toolkit'), $last_scan_text));
				echo '</p><ul style="margin-left:1.5em;list-style:disc;">';
				foreach ($files as $relative_path) {
					echo '<li><code>' . esc_html($relative_path) . '</code></li>';
				}
				echo '</ul></div>';
			}

			$nginx_notice = get_transient(self::NGINX_NOTICE_TRANSIENT);
			if (is_string($nginx_notice) && '' !== $nginx_notice) {
				echo '<div class="notice notice-info"><p><strong>' . esc_html__('WP Security Toolkit:', 'wp-security-toolkit') . '</strong><br>' . nl2br(esc_html($nginx_notice)) . '</p></div>';
				delete_transient(self::NGINX_NOTICE_TRANSIENT);
			}
		}

		/**
		 * @return list<string>
		 */
		private function get_blocked_extensions(): array {
			$default = [
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
			];

			$extensions = apply_filters('wpst_uploads_block_extensions', $default);
			if (! is_array($extensions)) {
				return $default;
			}

			$normalized = [];
			foreach ($extensions as $extension) {
				$extension = strtolower(trim((string) $extension));
				$extension = ltrim($extension, '.');
				if ('' !== $extension) {
					$normalized[] = $extension;
				}
			}

			if ([] === $normalized) {
				return $default;
			}

			return array_values(array_unique($normalized));
		}

		private function should_block_svg(): bool {
			return (bool) apply_filters('wpst_block_svg_uploads', true);
		}

		private function maybe_scan_uploads_directory(): void {
			$last_run = get_transient(self::SCAN_LAST_RUN_TRANSIENT);
			if (is_numeric($last_run) && (time() - (int) $last_run) < self::SCAN_INTERVAL) {
				return;
			}

			set_transient(self::SCAN_LAST_RUN_TRANSIENT, (string) time(), self::SCAN_INTERVAL);

			$upload_data = wp_upload_dir(null, false);
			$base_dir = isset($upload_data['basedir']) ? (string) $upload_data['basedir'] : '';
			if ('' === $base_dir || ! is_dir($base_dir) || ! is_readable($base_dir)) {
				return;
			}

			$extensions = apply_filters('wpst_uploads_scan_extensions', ['php', 'phtml', 'phar', 'pht']);
			if (! is_array($extensions)) {
				$extensions = ['php', 'phtml', 'phar', 'pht'];
			}

			$needle_extensions = [];
			foreach ($extensions as $extension) {
				$extension = strtolower(trim((string) $extension));
				$extension = ltrim($extension, '.');
				if ('' !== $extension) {
					$needle_extensions[] = $extension;
				}
			}
			$needle_extensions = array_values(array_unique($needle_extensions));
			if ([] === $needle_extensions) {
				return;
			}

			$matches = [];
			$files_seen = 0;

			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator($base_dir, FilesystemIterator::SKIP_DOTS),
					RecursiveIteratorIterator::SELF_FIRST
				);
			} catch (Exception $exception) {
				return;
			}

			foreach ($iterator as $item) {
				if (! $item instanceof SplFileInfo) {
					continue;
				}

				if ($iterator->getDepth() > self::SCAN_MAX_DEPTH) {
					continue;
				}

				if ($item->isDir()) {
					continue;
				}

				$files_seen++;
				if ($files_seen > self::SCAN_MAX_FILES) {
					break;
				}

				$extension = strtolower((string) pathinfo($item->getFilename(), PATHINFO_EXTENSION));
				if ('' === $extension || ! in_array($extension, $needle_extensions, true)) {
					continue;
				}

				$relative_path = ltrim(str_replace($base_dir, '', $item->getPathname()), DIRECTORY_SEPARATOR);
				$matches[] = str_replace('\\', '/', $relative_path);
				if (count($matches) >= self::SCAN_MAX_RESULTS) {
					break;
				}
			}

			update_option(
				self::SCAN_RESULTS_OPTION,
				[
					'files' => $matches,
					'last_scan' => time(),
				],
				false
			);
		}

		private function maybe_write_htaccess_guard(): void {
			$upload_data = wp_upload_dir(null, false);
			$base_dir = isset($upload_data['basedir']) ? (string) $upload_data['basedir'] : '';
			if ('' === $base_dir || ! is_dir($base_dir) || ! is_writable($base_dir)) {
				return;
			}

			if (! $this->is_apache_like_server()) {
				$message = (string) apply_filters('wpst_uploads_nginx_snippet_notice', $this->default_nginx_notice());
				if ('' !== trim($message)) {
					set_transient(self::NGINX_NOTICE_TRANSIENT, $message, DAY_IN_SECONDS);
				}
				return;
			}

			$htaccess_path = trailingslashit($base_dir) . '.htaccess';
			$begin_marker = '# BEGIN WPST Uploads Guard';
			$end_marker = '# END WPST Uploads Guard';
			$guard_block = $begin_marker . "\n"
				. '<FilesMatch "\\.(php|phtml|phar|pht|php[0-9])$">' . "\n"
				. '  Require all denied' . "\n"
				. '</FilesMatch>' . "\n"
				. $end_marker;

			$current = '';
			if (file_exists($htaccess_path) && is_readable($htaccess_path)) {
				$contents = file_get_contents($htaccess_path);
				if (is_string($contents)) {
					$current = $contents;
				}
			}

			$new_contents = '';
			if ('' === $current) {
				$new_contents = $guard_block . "\n";
			} elseif (false !== strpos($current, $begin_marker) && false !== strpos($current, $end_marker)) {
				$new_contents = (string) preg_replace(
					'/' . preg_quote($begin_marker, '/') . '.*?' . preg_quote($end_marker, '/') . '/s',
					$guard_block,
					$current
				);
			} else {
				$new_contents = rtrim($current) . "\n\n" . $guard_block . "\n";
			}

			if ($new_contents !== $current) {
				wp_mkdir_p($base_dir);
				file_put_contents($htaccess_path, $new_contents, LOCK_EX);
			}
		}

		private function is_apache_like_server(): bool {
			$software = '';
			if (isset($_SERVER['SERVER_SOFTWARE'])) {
				$software = (string) $_SERVER['SERVER_SOFTWARE'];
			}

			if ('' === $software) {
				return false;
			}

			$software = strtolower($software);
			return false !== strpos($software, 'apache') || false !== strpos($software, 'litespeed');
		}

		private function default_nginx_notice(): string {
			return "Uploads auto .htaccess writing is enabled, but this server does not appear to be Apache/LiteSpeed.\n"
				. "For Nginx, add a rule similar to:\n"
				. "location ~* /wp-content/uploads/.*\\.(php|phtml|phar|pht|php[0-9])$ { deny all; }";
		}
	}
}

$wpst_uploads_execution_guard = new WPST_Uploads_Execution_Guard();
$wpst_uploads_execution_guard->init();
add_action('muplugins_loaded', [$wpst_uploads_execution_guard, 'init'], 0);

/*
Example filter usage (put into a must-use plugin or theme bootstrap):

// Disable uploads scanning.
add_filter('wpst_uploads_scan_enabled', '__return_false');

// Enable uploads .htaccess auto-write (only meaningful on Apache/LiteSpeed).
add_filter('wpst_uploads_auto_write_htaccess', '__return_true');

// Keep SVG blocked.
add_filter('wpst_block_svg_uploads', '__return_true');

// Extend dangerous extension block list.
add_filter('wpst_uploads_block_extensions', static function (array $extensions): array {
	$extensions[] = 'shtml';
	return array_values(array_unique($extensions));
});
*/
