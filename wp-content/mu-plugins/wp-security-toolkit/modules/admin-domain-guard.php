<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_Restrict_Admin_By_Domain')) {
	final class WPST_Restrict_Admin_By_Domain {
		private const ADMIN_ROLE = 'administrator';

		/**
		 * @var array<int, string>|null
		 */
		private ?array $allowed_domains_cache = null;

		public function register_hooks(): void {
			add_action('user_profile_update_errors', [$this, 'block_disallowed_admin_in_profile_ui'], 10, 3);
			add_filter('wp_pre_insert_user_data', [$this, 'block_disallowed_admin_on_pre_insert'], 10, 4);
			add_action('set_user_role', [$this, 'enforce_admin_restriction_on_set_role'], 10, 3);
			add_action('add_user_role', [$this, 'enforce_admin_restriction_on_add_role'], 10, 2);
			add_action('profile_update', [$this, 'enforce_admin_restriction_on_profile_update'], 10, 2);
		}

		public function block_disallowed_admin_in_profile_ui(\WP_Error $errors, bool $update, \stdClass $user): void {
			if (empty($_POST['role']) || self::ADMIN_ROLE !== (string) $_POST['role']) {
				return;
			}

			$email = (string) ($user->user_email ?? $_POST['email'] ?? '');
			if ($this->is_allowed_email_domain($email)) {
				return;
			}

			$errors->add(
				'wpst_admin_domain_restricted',
				__('Administrator role can only be assigned to users with an allowlisted email domain.', 'wp-security-toolkit')
			);
		}

		/**
		 * @param array<string, mixed> $data
		 * @param array<string, mixed> $userdata
		 * @return array<string, mixed>
		 */
		public function block_disallowed_admin_on_pre_insert(array $data, bool $update, int $user_id, array $userdata): array {
			$role = '';
			if (isset($userdata['role'])) {
				$role = (string) $userdata['role'];
			} elseif (isset($data['role'])) {
				$role = (string) $data['role'];
			}

			if (self::ADMIN_ROLE !== $role) {
				return $data;
			}

			$email = (string) ($userdata['user_email'] ?? $data['user_email'] ?? '');
			if ($this->is_allowed_email_domain($email)) {
				return $data;
			}

			$fallback_role = $this->fallback_role();
			$data['role'] = $fallback_role;
			$userdata['role'] = $fallback_role;

			return $data;
		}

		/**
		 * @param array<int, string> $old_roles
		 */
		public function enforce_admin_restriction_on_set_role(int $user_id, string $role, array $old_roles): void {
			if (self::ADMIN_ROLE !== $role) {
				return;
			}

			$this->demote_if_disallowed($user_id);
		}

		public function enforce_admin_restriction_on_add_role(int $user_id, string $role): void {
			if (self::ADMIN_ROLE !== $role) {
				return;
			}

			$this->demote_if_disallowed($user_id);
		}

		public function enforce_admin_restriction_on_profile_update(int $user_id, \WP_User $old_user_data): void {
			$user = get_userdata($user_id);
			if (! ($user instanceof \WP_User)) {
				return;
			}

			if (! in_array(self::ADMIN_ROLE, (array) $user->roles, true)) {
				return;
			}

			if ($this->is_allowed_email_domain((string) $user->user_email)) {
				return;
			}

			$this->demote_user($user);
		}

		private function demote_if_disallowed(int $user_id): void {
			$user = get_userdata($user_id);
			if (! ($user instanceof \WP_User)) {
				return;
			}

			if ($this->is_allowed_email_domain((string) $user->user_email)) {
				return;
			}

			$this->demote_user($user);
		}

		private function demote_user(\WP_User $user): void {
			remove_action('set_user_role', [$this, 'enforce_admin_restriction_on_set_role'], 10, 3);
			remove_action('add_user_role', [$this, 'enforce_admin_restriction_on_add_role'], 10, 2);
			remove_action('profile_update', [$this, 'enforce_admin_restriction_on_profile_update'], 10, 2);

			$user->remove_role(self::ADMIN_ROLE);
			if ([] === (array) $user->roles) {
				$user->set_role($this->fallback_role());
			}

			add_action('set_user_role', [$this, 'enforce_admin_restriction_on_set_role'], 10, 3);
			add_action('add_user_role', [$this, 'enforce_admin_restriction_on_add_role'], 10, 2);
			add_action('profile_update', [$this, 'enforce_admin_restriction_on_profile_update'], 10, 2);
		}

		private function fallback_role(): string {
			$role = (string) apply_filters('wpst_disallowed_admin_fallback_role', 'subscriber');

			$wp_roles = wp_roles();
			if ('' !== $role && get_role($role) && $wp_roles && isset($wp_roles->roles[$role])) {
				return $role;
			}

			return 'subscriber';
		}

		/**
		 * @return array<int, string>
		 */
		private function allowed_domains(): array {
			if (null !== $this->allowed_domains_cache) {
				return $this->allowed_domains_cache;
			}

			$domains = apply_filters('wpst_allowed_admin_email_domains', []);
			if (! is_array($domains)) {
				$this->allowed_domains_cache = [];
				return $this->allowed_domains_cache;
			}

			$normalized = [];
			foreach ($domains as $domain) {
				if (! is_scalar($domain)) {
					continue;
				}

				$normalized_domain = $this->normalize_domain((string) $domain);
				if ('' !== $normalized_domain) {
					$normalized[] = $normalized_domain;
				}
			}

			$this->allowed_domains_cache = array_values(array_unique($normalized));
			return $this->allowed_domains_cache;
		}

		private function is_allowed_email_domain(string $email): bool {
			$domain = $this->extract_email_domain($email);
			if ('' === $domain) {
				return false;
			}

			foreach ($this->allowed_domains() as $allowed_domain) {
				if ($this->domain_matches($domain, $allowed_domain)) {
					return true;
				}
			}

			return false;
		}

		private function extract_email_domain(string $email): string {
			$at_position = strrpos($email, '@');
			if (false === $at_position) {
				return '';
			}

			$domain = substr($email, $at_position + 1);
			if (false === $domain || '' === $domain) {
				return '';
			}

			return $this->normalize_domain($domain);
		}

		private function domain_matches(string $domain, string $allowed_domain): bool {
			if (str_starts_with($allowed_domain, '*.')) {
				$base_domain = substr($allowed_domain, 2);
				if ('' === $base_domain) {
					return false;
				}

				$matches_subdomain = str_ends_with($domain, '.' . $base_domain);
				if ($matches_subdomain) {
					return true;
				}

				$includes_root = (bool) apply_filters('wpst_wildcard_includes_root_domain', false, $base_domain);
				return $includes_root && $domain === $base_domain;
			}

			return $domain === $allowed_domain;
		}

		private function normalize_domain(string $domain): string {
			$normalized = strtolower(trim($domain));
			if ('' === $normalized) {
				return '';
			}

			$has_wildcard = str_starts_with($normalized, '*.');
			$domain_without_wildcard = $has_wildcard ? substr($normalized, 2) : $normalized;
			if ('' === $domain_without_wildcard) {
				return '';
			}

			if (function_exists('idn_to_ascii')) {
				$idn_ascii = idn_to_ascii($domain_without_wildcard, IDNA_DEFAULT);
				if (false !== $idn_ascii && '' !== $idn_ascii) {
					$domain_without_wildcard = strtolower($idn_ascii);
				}
			}

			return $has_wildcard ? '*.' . $domain_without_wildcard : $domain_without_wildcard;
		}
	}

	(new WPST_Restrict_Admin_By_Domain())->register_hooks();
}
