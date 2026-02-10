<?php
/**
 * Plugin Name: WP Security Toolkit - File Lockdown
 * Description: Disables wp-admin file editors and optionally disables file modifications by environment.
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_File_Lockdown')) {
	final class WPST_File_Lockdown {
		private bool $initialized = false;

		public function init(): void {
			if ($this->initialized) {
				return;
			}

			$this->initialized = true;
			$this->define_disallow_file_edit();
			$this->define_disallow_file_mods();
		}

		private function define_disallow_file_edit(): void {
			if (defined('DISALLOW_FILE_EDIT')) {
				return;
			}

			$default = true;
			$should_disallow = (bool) apply_filters('wpst_disallow_file_edit', $default);
			define('DISALLOW_FILE_EDIT', $should_disallow);
		}

		private function define_disallow_file_mods(): void {
			if (defined('DISALLOW_FILE_MODS')) {
				return;
			}

			$environment = $this->environment_type();
			$default = in_array($environment, ['local', 'development', 'staging'], true);
			$should_disallow = (bool) apply_filters('wpst_disallow_file_mods', $default);
			define('DISALLOW_FILE_MODS', $should_disallow);
		}

		private function environment_type(): string {
			$environment = 'production';

			if (function_exists('wp_get_environment_type')) {
				$environment = (string) wp_get_environment_type();
			} elseif (defined('WP_ENVIRONMENT_TYPE')) {
				$environment = (string) WP_ENVIRONMENT_TYPE;
			}

			$environment = strtolower(trim($environment));
			$environment = (string) apply_filters('wpst_environment_type', $environment);
			$environment = strtolower(trim($environment));

			if ('' === $environment) {
				return 'production';
			}

			return $environment;
		}
	}
}

$wpst_file_lockdown = new WPST_File_Lockdown();
$wpst_file_lockdown->init();
add_action('muplugins_loaded', [$wpst_file_lockdown, 'init'], 0);
