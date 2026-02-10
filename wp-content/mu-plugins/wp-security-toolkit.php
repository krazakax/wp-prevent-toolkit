<?php
/**
 * Plugin Name: WP Security Toolkit
 * Description: Consolidated MU security modules loader for WordPress hardening controls.
 * Version: 1.0.0
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

require_once __DIR__ . '/wp-security-toolkit/loader.php';
