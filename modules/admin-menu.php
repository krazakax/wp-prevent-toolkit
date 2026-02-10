<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Admin_Menu')) {
	final class WPST_Admin_Menu {
		private const MENU_SLUG = 'wp-security-toolkit';

		public function register_hooks(): void {
			add_action('admin_menu', [$this, 'register_admin_menu'], 9);
		}

		public function register_admin_menu(): void {
			add_menu_page(
				esc_html__('WP Security Toolkit', 'wp-security-toolkit'),
				esc_html__('WP Security Toolkit', 'wp-security-toolkit'),
				$this->menu_capability(),
				self::MENU_SLUG,
				[$this, 'render_overview_page'],
				'dashicons-shield',
				$this->menu_position()
			);
		}

		public function render_overview_page(): void {
			if (! current_user_can($this->menu_capability())) {
				wp_die(esc_html__('You are not allowed to access this page.', 'wp-security-toolkit'), 403);
			}
			?>
			<div class="wrap">
				<h1><?php echo esc_html__('WP Security Toolkit', 'wp-security-toolkit'); ?></h1>
				<p><?php echo esc_html__('Use the submenus to configure toolkit modules.', 'wp-security-toolkit'); ?></p>
				<ul>
					<li><a href="<?php echo esc_url(admin_url('admin.php?page=wpst-diagnostics')); ?>"><?php echo esc_html__('Diagnostics', 'wp-security-toolkit'); ?></a></li>
					<li><a href="<?php echo esc_url(admin_url('admin.php?page=wpst-rate-limiting')); ?>"><?php echo esc_html__('Rate Limiting', 'wp-security-toolkit'); ?></a></li>
				</ul>
			</div>
			<?php
		}

		private function menu_capability(): string {
			$capability = apply_filters('wpst_admin_menu_capability', 'manage_options');
			return is_string($capability) && '' !== $capability ? $capability : 'manage_options';
		}

		private function menu_position(): int {
			$position = apply_filters('wpst_admin_menu_position', 80);
			return is_int($position) ? $position : 80;
		}
	}
}

$bootstrap = static function (): void {
	$admin_menu = new WPST_Admin_Menu();
	$admin_menu->register_hooks();
};

if (did_action('muplugins_loaded')) {
	$bootstrap();
} else {
	add_action('plugins_loaded', $bootstrap);
}
