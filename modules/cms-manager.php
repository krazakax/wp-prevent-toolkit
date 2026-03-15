<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
	exit;
}

if (! class_exists('WPST_CMS_Manager')) {
	final class WPST_CMS_Manager {
		private const PAGE_SLUG = 'wpst-cms-manager';
		private const SETTINGS_PAGE_SLUG = 'wpst-cms-settings';
		private const SEO_NONCE_ACTION = 'wpst_seo_meta_nonce_action';
		private const SEO_NONCE_NAME = 'wpst_seo_meta_nonce';

		/**
		 * @var list<string>
		 */
		private array $seo_post_types = ['post', 'page'];

		public function register_hooks(): void {
			add_action('admin_menu', [$this, 'register_admin_menu'], 50);
			add_action('admin_post_wpst_cms_create_user', [$this, 'handle_create_user']);
			add_action('admin_post_wpst_cms_create_content', [$this, 'handle_create_content']);
			add_action('admin_post_wpst_cms_create_sample_pages', [$this, 'handle_create_sample_pages']);
			add_action('admin_post_wpst_cms_save_settings', [$this, 'handle_save_settings']);

			add_action('add_meta_boxes', [$this, 'register_seo_meta_boxes']);
			add_action('save_post', [$this, 'save_seo_meta']);

			add_shortcode('wpst_blog_archive', [$this, 'render_blog_archive_shortcode']);
			add_shortcode('wpst_blog_single', [$this, 'render_blog_single_shortcode']);
			add_shortcode('wpst_login_form', [$this, 'render_login_form_shortcode']);

			add_action('admin_notices', [$this, 'render_admin_notices']);
		}



		public function render_admin_notices(): void {
			if (! is_admin() || ! current_user_can('manage_options')) {
				return;
			}

			$notice = isset($_GET['wpst_notice']) ? sanitize_key((string) wp_unslash($_GET['wpst_notice'])) : '';
			if ('' === $notice) {
				return;
			}

			$messages = [
				'user_created' => __('User created successfully.', 'wp-security-toolkit'),
				'content_created' => __('Content created successfully.', 'wp-security-toolkit'),
				'sample_pages_created' => __('Sample Home and Login pages are ready.', 'wp-security-toolkit'),
				'settings_saved' => __('Settings saved successfully.', 'wp-security-toolkit'),
				'missing_required_user_fields' => __('Please provide all required user fields.', 'wp-security-toolkit'),
				'user_creation_failed' => __('User creation failed. Please review inputs and try again.', 'wp-security-toolkit'),
				'missing_content_title' => __('Content title is required.', 'wp-security-toolkit'),
				'content_creation_failed' => __('Content creation failed. Please try again.', 'wp-security-toolkit'),
				'sample_pages_creation_failed' => __('Could not create sample pages. Please try again.', 'wp-security-toolkit'),
			];

			if (! isset($messages[$notice])) {
				return;
			}

			$class = in_array($notice, ['user_created', 'content_created', 'sample_pages_created', 'settings_saved'], true)
				? 'notice notice-success'
				: 'notice notice-error';

			echo '<div class="' . esc_attr($class) . '"><p>' . esc_html((string) $messages[$notice]) . '</p></div>';
		}

		public function register_admin_menu(): void {
			add_submenu_page(
				'wp-security-toolkit',
				__('CMS Manager', 'wp-security-toolkit'),
				__('CMS Manager', 'wp-security-toolkit'),
				'manage_options',
				self::PAGE_SLUG,
				[$this, 'render_cms_manager_page']
			);

			add_submenu_page(
				'wp-security-toolkit',
				__('CMS Settings', 'wp-security-toolkit'),
				__('CMS Settings', 'wp-security-toolkit'),
				'manage_options',
				self::SETTINGS_PAGE_SLUG,
				[$this, 'render_settings_page']
			);
		}

		public function render_cms_manager_page(): void {
			if (! current_user_can('manage_options')) {
				wp_die(esc_html__('You are not allowed to access this page.', 'wp-security-toolkit'), 403);
			}

			$roles = get_editable_roles();
			?>
			<div class="wrap">
				<h1><?php echo esc_html__('CMS Manager', 'wp-security-toolkit'); ?></h1>
				<p><?php echo esc_html__('Central CMS controls for users, pages, posts, and publishing helpers.', 'wp-security-toolkit'); ?></p>

				<h2><?php echo esc_html__('Content shortcuts', 'wp-security-toolkit'); ?></h2>
				<ul>
					<li><a href="<?php echo esc_url(admin_url('edit.php?post_type=page')); ?>"><?php echo esc_html__('Manage Pages', 'wp-security-toolkit'); ?></a></li>
					<li><a href="<?php echo esc_url(admin_url('post-new.php?post_type=page')); ?>"><?php echo esc_html__('Add New Page', 'wp-security-toolkit'); ?></a></li>
					<li><a href="<?php echo esc_url(admin_url('edit.php')); ?>"><?php echo esc_html__('Manage Posts', 'wp-security-toolkit'); ?></a></li>
					<li><a href="<?php echo esc_url(admin_url('post-new.php')); ?>"><?php echo esc_html__('Add New Post', 'wp-security-toolkit'); ?></a></li>
					<li><a href="<?php echo esc_url(admin_url('users.php')); ?>"><?php echo esc_html__('Manage Users', 'wp-security-toolkit'); ?></a></li>
				</ul>

				<h2><?php echo esc_html__('Create user', 'wp-security-toolkit'); ?></h2>
				<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
					<input type="hidden" name="action" value="wpst_cms_create_user" />
					<?php wp_nonce_field('wpst_cms_create_user'); ?>
					<table class="form-table" role="presentation">
						<tr>
							<th><label for="wpst_new_user_login"><?php echo esc_html__('Username', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_new_user_login" name="user_login" class="regular-text" required /></td>
						</tr>
						<tr>
							<th><label for="wpst_new_user_email"><?php echo esc_html__('Email', 'wp-security-toolkit'); ?></label></th>
							<td><input type="email" id="wpst_new_user_email" name="user_email" class="regular-text" required /></td>
						</tr>
						<tr>
							<th><label for="wpst_new_user_password"><?php echo esc_html__('Password', 'wp-security-toolkit'); ?></label></th>
							<td><input type="password" id="wpst_new_user_password" name="user_password" class="regular-text" required /></td>
						</tr>
						<tr>
							<th><label for="wpst_new_user_role"><?php echo esc_html__('Role', 'wp-security-toolkit'); ?></label></th>
							<td>
								<select id="wpst_new_user_role" name="user_role">
									<?php foreach ($roles as $role_key => $role_data) : ?>
										<option value="<?php echo esc_attr((string) $role_key); ?>"><?php echo esc_html((string) ($role_data['name'] ?? $role_key)); ?></option>
									<?php endforeach; ?>
								</select>
							</td>
						</tr>
					</table>
					<?php submit_button(__('Create User', 'wp-security-toolkit')); ?>
				</form>

				<h2><?php echo esc_html__('Quick create content', 'wp-security-toolkit'); ?></h2>
				<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
					<input type="hidden" name="action" value="wpst_cms_create_content" />
					<?php wp_nonce_field('wpst_cms_create_content'); ?>
					<table class="form-table" role="presentation">
						<tr>
							<th><label for="wpst_content_type"><?php echo esc_html__('Content type', 'wp-security-toolkit'); ?></label></th>
							<td>
								<select id="wpst_content_type" name="content_type">
									<option value="page"><?php echo esc_html__('Page', 'wp-security-toolkit'); ?></option>
									<option value="post"><?php echo esc_html__('Post', 'wp-security-toolkit'); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><label for="wpst_content_title"><?php echo esc_html__('Title', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_content_title" name="content_title" class="regular-text" required /></td>
						</tr>
						<tr>
							<th><label for="wpst_content_slug"><?php echo esc_html__('Slug', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_content_slug" name="content_slug" class="regular-text" /></td>
						</tr>
						<tr>
							<th><label for="wpst_content_status"><?php echo esc_html__('Status', 'wp-security-toolkit'); ?></label></th>
							<td>
								<select id="wpst_content_status" name="content_status">
									<option value="draft"><?php echo esc_html__('Draft', 'wp-security-toolkit'); ?></option>
									<option value="publish"><?php echo esc_html__('Published', 'wp-security-toolkit'); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><label for="wpst_content_body"><?php echo esc_html__('Content', 'wp-security-toolkit'); ?></label></th>
							<td><textarea id="wpst_content_body" name="content_body" class="large-text" rows="8"></textarea></td>
						</tr>
					</table>
					<?php submit_button(__('Create Content', 'wp-security-toolkit')); ?>
				</form>

				<h2><?php echo esc_html__('Blog templates', 'wp-security-toolkit'); ?></h2>
				<p><?php echo esc_html__('Use these shortcodes on any page to output a basic blog archive or single post view.', 'wp-security-toolkit'); ?></p>
				<code>[wpst_blog_archive posts_per_page="10"]</code><br />
				<code>[wpst_blog_single id="123"]</code>

				<h2><?php echo esc_html__('Sample pages', 'wp-security-toolkit'); ?></h2>
				<p><?php echo esc_html__('Generate a starter Home page and Login page you can customize.', 'wp-security-toolkit'); ?></p>
				<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
					<input type="hidden" name="action" value="wpst_cms_create_sample_pages" />
					<?php wp_nonce_field('wpst_cms_create_sample_pages'); ?>
					<?php submit_button(__('Create Sample Home + Login Pages', 'wp-security-toolkit'), 'secondary', 'submit', false); ?>
				</form>
			</div>
			<?php
		}

		public function render_settings_page(): void {
			if (! current_user_can('manage_options')) {
				wp_die(esc_html__('You are not allowed to access this page.', 'wp-security-toolkit'), 403);
			}
			?>
			<div class="wrap">
				<h1><?php echo esc_html__('CMS Settings', 'wp-security-toolkit'); ?></h1>
				<p><?php echo esc_html__('WordPress-like general settings for title, tagline, and publishing defaults.', 'wp-security-toolkit'); ?></p>
				<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
					<input type="hidden" name="action" value="wpst_cms_save_settings" />
					<?php wp_nonce_field('wpst_cms_save_settings'); ?>
					<table class="form-table" role="presentation">
						<tr>
							<th><label for="wpst_blogname"><?php echo esc_html__('Site Title', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_blogname" name="blogname" class="regular-text" value="<?php echo esc_attr((string) get_option('blogname', '')); ?>" /></td>
						</tr>
						<tr>
							<th><label for="wpst_blogdescription"><?php echo esc_html__('Tagline', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_blogdescription" name="blogdescription" class="regular-text" value="<?php echo esc_attr((string) get_option('blogdescription', '')); ?>" /></td>
						</tr>
						<tr>
							<th><label for="wpst_admin_email"><?php echo esc_html__('Admin Email', 'wp-security-toolkit'); ?></label></th>
							<td><input type="email" id="wpst_admin_email" name="admin_email" class="regular-text" value="<?php echo esc_attr((string) get_option('admin_email', '')); ?>" /></td>
						</tr>
						<tr>
							<th><label for="wpst_timezone_string"><?php echo esc_html__('Timezone', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_timezone_string" name="timezone_string" class="regular-text" value="<?php echo esc_attr((string) get_option('timezone_string', '')); ?>" placeholder="UTC" /></td>
						</tr>
						<tr>
							<th><label for="wpst_date_format"><?php echo esc_html__('Date Format', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_date_format" name="date_format" class="regular-text" value="<?php echo esc_attr((string) get_option('date_format', 'F j, Y')); ?>" /></td>
						</tr>
						<tr>
							<th><label for="wpst_time_format"><?php echo esc_html__('Time Format', 'wp-security-toolkit'); ?></label></th>
							<td><input type="text" id="wpst_time_format" name="time_format" class="regular-text" value="<?php echo esc_attr((string) get_option('time_format', 'g:i a')); ?>" /></td>
						</tr>
						<tr>
							<th><label for="wpst_posts_per_page"><?php echo esc_html__('Posts Per Page', 'wp-security-toolkit'); ?></label></th>
							<td><input type="number" min="1" max="100" id="wpst_posts_per_page" name="posts_per_page" value="<?php echo esc_attr((string) get_option('posts_per_page', 10)); ?>" /></td>
						</tr>
					</table>
					<?php submit_button(__('Save Settings', 'wp-security-toolkit')); ?>
				</form>
			</div>
			<?php
		}

		public function handle_create_user(): void {
			if (! current_user_can('create_users') || ! current_user_can('promote_users')) {
				wp_die(esc_html__('You are not allowed to create users.', 'wp-security-toolkit'), 403);
			}
			check_admin_referer('wpst_cms_create_user');

			$user_login = isset($_POST['user_login']) ? sanitize_user((string) wp_unslash($_POST['user_login']), true) : '';
			$user_email = isset($_POST['user_email']) ? sanitize_email((string) wp_unslash($_POST['user_email'])) : '';
			$user_password = isset($_POST['user_password']) ? (string) wp_unslash($_POST['user_password']) : '';
			$user_role = isset($_POST['user_role']) ? sanitize_key((string) wp_unslash($_POST['user_role'])) : 'subscriber';

			$roles = wp_roles();
			if (! ($roles instanceof WP_Roles) || ! isset($roles->roles[$user_role])) {
				$user_role = 'subscriber';
			}

			if ('' === $user_login || '' === $user_email || '' === $user_password) {
				$this->redirect_with_notice('missing_required_user_fields');
			}

			$result = wp_insert_user([
				'user_login' => $user_login,
				'user_email' => $user_email,
				'user_pass' => $user_password,
				'role' => $user_role,
			]);

			if ($result instanceof WP_Error) {
				$this->redirect_with_notice('user_creation_failed');
			}

			$this->redirect_with_notice('user_created');
		}

		public function handle_create_content(): void {
			if (! current_user_can('edit_posts')) {
				wp_die(esc_html__('You are not allowed to create content.', 'wp-security-toolkit'), 403);
			}
			check_admin_referer('wpst_cms_create_content');

			$post_type = isset($_POST['content_type']) ? sanitize_key((string) wp_unslash($_POST['content_type'])) : 'post';
			if (! in_array($post_type, ['post', 'page'], true)) {
				$post_type = 'post';
			}

			$post_status = isset($_POST['content_status']) ? sanitize_key((string) wp_unslash($_POST['content_status'])) : 'draft';
			if (! in_array($post_status, ['draft', 'publish'], true)) {
				$post_status = 'draft';
			}

			$post_title = isset($_POST['content_title']) ? sanitize_text_field((string) wp_unslash($_POST['content_title'])) : '';
			$post_slug = isset($_POST['content_slug']) ? sanitize_title((string) wp_unslash($_POST['content_slug'])) : '';
			$post_content = isset($_POST['content_body']) ? wp_kses_post((string) wp_unslash($_POST['content_body'])) : '';

			if ('' === $post_title) {
				$this->redirect_with_notice('missing_content_title');
			}

			$post_id = wp_insert_post([
				'post_type' => $post_type,
				'post_status' => $post_status,
				'post_title' => $post_title,
				'post_content' => $post_content,
				'post_name' => $post_slug,
			], true);

			if ($post_id instanceof WP_Error) {
				$this->redirect_with_notice('content_creation_failed');
			}

			$target = add_query_arg(
				[
					'page' => self::PAGE_SLUG,
					'wpst_notice' => 'content_created',
				],
				admin_url('admin.php')
			);

			wp_safe_redirect($target);
			exit;
		}

		public function handle_save_settings(): void {
			if (! current_user_can('manage_options')) {
				wp_die(esc_html__('You are not allowed to update settings.', 'wp-security-toolkit'), 403);
			}
			check_admin_referer('wpst_cms_save_settings');

			$updates = [
				'blogname' => isset($_POST['blogname']) ? sanitize_text_field((string) wp_unslash($_POST['blogname'])) : '',
				'blogdescription' => isset($_POST['blogdescription']) ? sanitize_text_field((string) wp_unslash($_POST['blogdescription'])) : '',
				'admin_email' => isset($_POST['admin_email']) ? sanitize_email((string) wp_unslash($_POST['admin_email'])) : '',
				'timezone_string' => isset($_POST['timezone_string']) ? sanitize_text_field((string) wp_unslash($_POST['timezone_string'])) : '',
				'date_format' => isset($_POST['date_format']) ? sanitize_text_field((string) wp_unslash($_POST['date_format'])) : 'F j, Y',
				'time_format' => isset($_POST['time_format']) ? sanitize_text_field((string) wp_unslash($_POST['time_format'])) : 'g:i a',
				'posts_per_page' => isset($_POST['posts_per_page']) ? (int) $_POST['posts_per_page'] : 10,
			];

			$updates['posts_per_page'] = max(1, min(100, $updates['posts_per_page']));

			foreach ($updates as $key => $value) {
				update_option($key, $value);
			}

			$target = add_query_arg(
				[
					'page' => self::SETTINGS_PAGE_SLUG,
					'wpst_notice' => 'settings_saved',
				],
				admin_url('admin.php')
			);
			wp_safe_redirect($target);
			exit;
		}

		public function handle_create_sample_pages(): void {
			if (! current_user_can('edit_pages')) {
				wp_die(esc_html__('You are not allowed to create sample pages.', 'wp-security-toolkit'), 403);
			}
			check_admin_referer('wpst_cms_create_sample_pages');

			$home_content = '<!-- wp:heading {"level":1} -->'
				. '<h1>' . esc_html__('Welcome to Our Site', 'wp-security-toolkit') . '</h1>'
				. '<!-- /wp:heading -->'
				. '<!-- wp:paragraph -->'
				. '<p>' . esc_html__('This is a sample homepage. Update this section with your brand message, highlights, and key calls to action.', 'wp-security-toolkit') . '</p>'
				. '<!-- /wp:paragraph -->'
				. '<!-- wp:buttons -->'
				. '<div class="wp-block-buttons">'
				. '<!-- wp:button -->'
				. '<div class="wp-block-button"><a class="wp-block-button__link wp-element-button" href="/login">' . esc_html__('Login', 'wp-security-toolkit') . '</a></div>'
				. '<!-- /wp:button -->'
				. '</div>'
				. '<!-- /wp:buttons -->';

			$login_content = '<!-- wp:heading {"level":1} -->'
				. '<h1>' . esc_html__('Login', 'wp-security-toolkit') . '</h1>'
				. '<!-- /wp:heading -->'
				. '<!-- wp:paragraph -->'
				. '<p>' . esc_html__('Use the form below to sign in to your account.', 'wp-security-toolkit') . '</p>'
				. '<!-- /wp:paragraph -->'
				. '<!-- wp:shortcode -->[wpst_login_form]<!-- /wp:shortcode -->';

			$home_page_id = $this->upsert_page('home', __('Home', 'wp-security-toolkit'), $home_content);
			$login_page_id = $this->upsert_page('login', __('Login', 'wp-security-toolkit'), $login_content);

			if ($home_page_id < 1 || $login_page_id < 1) {
				$this->redirect_with_notice('sample_pages_creation_failed');
			}

			$this->redirect_with_notice('sample_pages_created');
		}

		public function register_seo_meta_boxes(): void {
			foreach ($this->seo_post_types as $post_type) {
				add_meta_box(
					'wpst_seo_meta',
					__('SEO', 'wp-security-toolkit'),
					[$this, 'render_seo_meta_box'],
					$post_type,
					'normal',
					'default'
				);
			}
		}

		/**
		 * @param WP_Post $post
		 */
		public function render_seo_meta_box($post): void {
			$seo_title = (string) get_post_meta($post->ID, '_wpst_seo_title', true);
			$seo_description = (string) get_post_meta($post->ID, '_wpst_seo_description', true);
			$seo_robots = (string) get_post_meta($post->ID, '_wpst_seo_robots', true);
			$seo_canonical = (string) get_post_meta($post->ID, '_wpst_seo_canonical', true);

			wp_nonce_field(self::SEO_NONCE_ACTION, self::SEO_NONCE_NAME);
			?>
			<p>
				<label for="wpst_seo_title"><strong><?php echo esc_html__('SEO Title', 'wp-security-toolkit'); ?></strong></label><br />
				<input type="text" id="wpst_seo_title" name="wpst_seo_title" class="widefat" value="<?php echo esc_attr($seo_title); ?>" />
			</p>
			<p>
				<label for="wpst_seo_description"><strong><?php echo esc_html__('SEO Description', 'wp-security-toolkit'); ?></strong></label><br />
				<textarea id="wpst_seo_description" name="wpst_seo_description" class="widefat" rows="3"><?php echo esc_textarea($seo_description); ?></textarea>
			</p>
			<p>
				<label for="wpst_seo_robots"><strong><?php echo esc_html__('Robots', 'wp-security-toolkit'); ?></strong></label><br />
				<select id="wpst_seo_robots" name="wpst_seo_robots">
					<option value="index,follow" <?php selected($seo_robots, 'index,follow'); ?>>index,follow</option>
					<option value="noindex,follow" <?php selected($seo_robots, 'noindex,follow'); ?>>noindex,follow</option>
					<option value="noindex,nofollow" <?php selected($seo_robots, 'noindex,nofollow'); ?>>noindex,nofollow</option>
				</select>
			</p>
			<p>
				<label for="wpst_seo_canonical"><strong><?php echo esc_html__('Canonical URL', 'wp-security-toolkit'); ?></strong></label><br />
				<input type="url" id="wpst_seo_canonical" name="wpst_seo_canonical" class="widefat" value="<?php echo esc_attr($seo_canonical); ?>" />
			</p>
			<?php
		}

		public function save_seo_meta(int $post_id): void {
			if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
				return;
			}

			if (! isset($_POST[self::SEO_NONCE_NAME]) || ! wp_verify_nonce((string) $_POST[self::SEO_NONCE_NAME], self::SEO_NONCE_ACTION)) {
				return;
			}

			if (! current_user_can('edit_post', $post_id)) {
				return;
			}

			$title = isset($_POST['wpst_seo_title']) ? sanitize_text_field((string) wp_unslash($_POST['wpst_seo_title'])) : '';
			$description = isset($_POST['wpst_seo_description']) ? sanitize_textarea_field((string) wp_unslash($_POST['wpst_seo_description'])) : '';
			$robots = isset($_POST['wpst_seo_robots']) ? sanitize_text_field((string) wp_unslash($_POST['wpst_seo_robots'])) : 'index,follow';
			$canonical = isset($_POST['wpst_seo_canonical']) ? esc_url_raw((string) wp_unslash($_POST['wpst_seo_canonical'])) : '';

			if (! in_array($robots, ['index,follow', 'noindex,follow', 'noindex,nofollow'], true)) {
				$robots = 'index,follow';
			}

			update_post_meta($post_id, '_wpst_seo_title', $title);
			update_post_meta($post_id, '_wpst_seo_description', $description);
			update_post_meta($post_id, '_wpst_seo_robots', $robots);
			update_post_meta($post_id, '_wpst_seo_canonical', $canonical);
		}

		/**
		 * @param array<string, string> $atts
		 */
		public function render_blog_archive_shortcode(array $atts = []): string {
			$defaults = [
				'posts_per_page' => (string) get_option('posts_per_page', 10),
			];
			$atts = shortcode_atts($defaults, $atts, 'wpst_blog_archive');
			$posts_per_page = max(1, (int) $atts['posts_per_page']);

			$query = new WP_Query([
				'post_type' => 'post',
				'post_status' => 'publish',
				'posts_per_page' => $posts_per_page,
			]);

			if (! $query->have_posts()) {
				return '<p>' . esc_html__('No blog posts found.', 'wp-security-toolkit') . '</p>';
			}

			ob_start();
			echo '<div class="wpst-blog-archive">';
			echo '<h2>' . esc_html__('Blog', 'wp-security-toolkit') . '</h2>';
			echo '<ul>';
			while ($query->have_posts()) {
				$query->the_post();
				echo '<li>';
				echo '<a href="' . esc_url((string) get_permalink()) . '">' . esc_html((string) get_the_title()) . '</a>';
				echo ' <small>(' . esc_html((string) get_the_date()) . ')</small>';
				echo '</li>';
			}
			echo '</ul>';
			echo '</div>';
			wp_reset_postdata();

			return (string) ob_get_clean();
		}

		/**
		 * @param array<string, string> $atts
		 */
		public function render_blog_single_shortcode(array $atts = []): string {
			$atts = shortcode_atts(['id' => '0'], $atts, 'wpst_blog_single');
			$post_id = (int) $atts['id'];
			if ($post_id < 1) {
				return '<p>' . esc_html__('Missing post id for blog single shortcode.', 'wp-security-toolkit') . '</p>';
			}

			$post = get_post($post_id);
			if (! ($post instanceof WP_Post) || 'post' !== $post->post_type || 'publish' !== $post->post_status) {
				return '<p>' . esc_html__('Blog post not found.', 'wp-security-toolkit') . '</p>';
			}

			ob_start();
			echo '<article class="wpst-blog-single">';
			echo '<h1>' . esc_html(get_the_title($post)) . '</h1>';
			echo '<p><small>' . esc_html((string) get_the_date('', $post)) . '</small></p>';
			echo wp_kses_post((string) apply_filters('the_content', (string) $post->post_content));
			echo '</article>';

			return (string) ob_get_clean();
		}


		public function render_login_form_shortcode(): string {
			if (is_user_logged_in()) {
				return '<p>' . esc_html__('You are already logged in.', 'wp-security-toolkit') . '</p>';
			}

			return wp_login_form([
				'echo' => false,
				'remember' => true,
				'redirect' => home_url('/'),
			]);
		}

		private function redirect_with_notice(string $notice): void {
			$target = add_query_arg(
				[
					'page' => self::PAGE_SLUG,
					'wpst_notice' => $notice,
				],
				admin_url('admin.php')
			);
			wp_safe_redirect($target);
			exit;
		}

		private function upsert_page(string $slug, string $title, string $content): int {
			$page = get_page_by_path($slug, OBJECT, 'page');

			$page_data = [
				'post_type' => 'page',
				'post_title' => $title,
				'post_content' => $content,
				'post_status' => 'publish',
				'post_name' => $slug,
			];

			if ($page instanceof WP_Post) {
				$page_data['ID'] = $page->ID;
			}

			$result = wp_insert_post($page_data, true);

			if ($result instanceof WP_Error) {
				return 0;
			}

			return (int) $result;
		}
	}
}

$bootstrap = static function (): void {
	$manager = new WPST_CMS_Manager();
	$manager->register_hooks();
};

if (did_action('muplugins_loaded')) {
	$bootstrap();
} else {
	add_action('plugins_loaded', $bootstrap);
}
