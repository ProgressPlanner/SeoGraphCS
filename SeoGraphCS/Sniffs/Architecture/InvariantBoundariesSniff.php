<?php
/**
 * Enforces SEO Graph architecture invariants.
 *
 * @package SeoGraphCS
 */

namespace SeoGraphCS\Sniffs\Architecture;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Enforces runtime architecture boundaries that must fail at the standards gate.
 */
class InvariantBoundariesSniff implements Sniff {

	/**
	 * Files already processed by this sniff.
	 *
	 * @var array<string, true>
	 */
	private array $processed = [];

	/**
	 * Filesystem-writing functions and WordPress helpers forbidden in runtime code.
	 *
	 * @var array<string, true>
	 */
	private const FORBIDDEN_WRITE_FUNCTIONS = [
		'chgrp'                         => true,
		'chmod'                         => true,
		'chown'                         => true,
		'copy'                          => true,
		'copy_dir'                      => true,
		'delete_temp_backup'            => true,
		'download_url'                  => true,
		'file_put_contents'             => true,
		'fputs'                         => true,
		'fwrite'                        => true,
		'insert_with_markers'           => true,
		'iis7_save_url_rewrite_rules'   => true,
		'link'                          => true,
		'media_handle_sideload'         => true,
		'media_handle_upload'           => true,
		'media_sideload_image'          => true,
		'mkdir'                         => true,
		'move_dir'                      => true,
		'move_uploaded_file'            => true,
		'rename'                        => true,
		'rmdir'                         => true,
		'save_mod_rewrite_rules'        => true,
		'symlink'                       => true,
		'tempnam'                       => true,
		'tmpfile'                       => true,
		'touch'                         => true,
		'unlink'                        => true,
		'unzip_file'                    => true,
		'wp_delete_file'                => true,
		'wp_delete_file_from_directory' => true,
		'wp_handle_sideload'            => true,
		'wp_handle_upload'              => true,
		'wp_mkdir_p'                    => true,
		'wp_tempnam'                    => true,
		'wp_upload_bits'                => true,
		'_wp_handle_upload'             => true,
	];

	/**
	 * Native WP-Cron scheduling functions forbidden in runtime code.
	 *
	 * Action Scheduler owns every SEO Graph background job. Inspection and
	 * cleanup APIs remain allowed because they do not create background work.
	 *
	 * @var array<string, true>
	 */
	private const FORBIDDEN_WP_CRON_SCHEDULING_FUNCTIONS = [
		'wp_reschedule_event'      => true,
		'wp_schedule_event'        => true,
		'wp_schedule_single_event' => true,
	];

	/**
	 * WP_Filesystem methods that mutate files or directories.
	 *
	 * @var array<string, true>
	 */
	private const FORBIDDEN_WP_FILESYSTEM_METHODS = [
		'chgrp'        => true,
		'chmod'        => true,
		'chown'        => true,
		'copy'         => true,
		'delete'       => true,
		'mkdir'        => true,
		'move'         => true,
		'put_contents' => true,
		'rmdir'        => true,
		'touch'        => true,
	];

	/**
	 * WordPress filesystem implementation classes.
	 *
	 * @var array<string, true>
	 */
	private const WP_FILESYSTEM_CLASSES = [
		'wp_filesystem_base'       => true,
		'wp_filesystem_direct'     => true,
		'wp_filesystem_ftpext'     => true,
		'wp_filesystem_ftpsockets' => true,
		'wp_filesystem_ssh2'       => true,
	];

	/**
	 * Wpdb methods that represent direct SQL access.
	 *
	 * @var array<string, true>
	 */
	private const WPDB_SQL_METHODS = [
		'delete'      => true,
		'get_col'     => true,
		'get_results' => true,
		'get_row'     => true,
		'get_var'     => true,
		'insert'      => true,
		'prepare'     => true,
		'query'       => true,
		'replace'     => true,
		'update'      => true,
	];

	/**
	 * Characters that may legally precede a real HTML tag start inside a shape.
	 * Regex delimiters, identifier characters and operators cannot introduce a
	 * tag, so inspection patterns such as /<title> or #<svg stay exempt while
	 * string starts and markup boundaries do not.
	 *
	 * @var string
	 */
	private const TAG_BOUNDARY_PRECEDING = " \t\n\r<>()[]{}='\"!-:=;";

	/**
	 * Runtime directories that the architecture sniff should not police.
	 *
	 * @var array<int, string>
	 */
	private const EXCLUDED_PATH_PARTS = [
		'/.git/',
		'/node_modules/',
		'/phpcs/',
		'/tests/',
		'/vendor/',
	];

	/**
	 * Registers for the first PHP token in each file.
	 *
	 * @return array<int, int>
	 */
	public function register(): array {
		return [ T_OPEN_TAG ];
	}

	/**
	 * Processes a file once.
	 *
	 * @param File $phpcs_file The PHPCS file.
	 * @param int  $stack_ptr  The token pointer.
	 *
	 * @return void
	 */
	public function process( File $phpcs_file, $stack_ptr ): void {
		$filename = $this->normalize_path( $phpcs_file->getFilename() );

		if ( isset( $this->processed[ $filename ] ) ) {
			return;
		}

		$this->processed[ $filename ] = true;

		if ( ! $this->should_scan( $filename ) ) {
			return;
		}

		$tokens                  = $phpcs_file->getTokens();
		$wp_filesystem_variables = $this->wp_filesystem_variables( $tokens );

		foreach ( $tokens as $ptr => $token ) {
			if ( $this->is_function_call( $tokens, $ptr ) ) {
				$this->check_function_call( $phpcs_file, $tokens, (int) $ptr, $filename );
			}

			if ( T_VARIABLE === $token['code'] && '$wpdb' === $token['content'] ) {
				$this->check_wpdb_method_call( $phpcs_file, $tokens, (int) $ptr, $filename );
			}

			if ( T_VARIABLE === $token['code'] && '$GLOBALS' === $token['content'] ) {
				$this->check_wpdb_global_method_call( $phpcs_file, $tokens, (int) $ptr, $filename );
			}

			if ( T_OBJECT_OPERATOR === $token['code'] ) {
				$this->check_wp_filesystem_method_call( $phpcs_file, $tokens, (int) $ptr, $wp_filesystem_variables );
			}

			if ( $this->is_string_statement( $tokens, (int) $ptr ) ) {
				$this->check_head_template_construction( $phpcs_file, $tokens, (int) $ptr, $filename );
			}
		}//end foreach
	}

	/**
	 * Checks a direct function call against invariant rules.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Function-name pointer.
	 * @param string            $filename   Normalized filename.
	 *
	 * @return void
	 */
	private function check_function_call( File $phpcs_file, array $tokens, int $ptr, string $filename ): void {
		$name     = $this->function_name( $tokens[ $ptr ]['content'] );
		$open_ptr = $this->next_non_empty( $tokens, $ptr );

		if ( isset( self::FORBIDDEN_WRITE_FUNCTIONS[ $name ] ) ) {
			$phpcs_file->addError(
				'Runtime code must not perform filesystem writes; serve generated resources virtually instead.',
				$ptr,
				'FilesystemWrite'
			);
		}

		if ( isset( self::FORBIDDEN_WP_CRON_SCHEDULING_FUNCTIONS[ $name ] ) ) {
			$phpcs_file->addError(
				'Background work must be queued through Action Scheduler, not native WP-Cron scheduling functions.',
				$ptr,
				'WpCronScheduling'
			);
		}

		if ( 'fopen' === $name && isset( $tokens[ $open_ptr ]['parenthesis_closer'] ) ) {
			$this->check_fopen_mode( $phpcs_file, $tokens, $ptr, (int) $open_ptr );
		}

		if ( 'flush_rewrite_rules' === $name && isset( $tokens[ $open_ptr ]['parenthesis_closer'] ) ) {
			$this->check_rewrite_flush( $phpcs_file, $tokens, $ptr, (int) $open_ptr );
		}

		if ( in_array( $name, [ 'add_option', 'update_option' ], true ) && isset( $tokens[ $open_ptr ]['parenthesis_closer'] ) ) {
			$this->check_option_autoload( $phpcs_file, $tokens, $ptr, (int) $open_ptr, $name );
		}

		if ( in_array( $name, [ 'wp_redirect', 'wp_safe_redirect' ], true ) && isset( $tokens[ $open_ptr ]['parenthesis_closer'] ) ) {
			$this->check_redirect_call( $phpcs_file, $tokens, $ptr, (int) $open_ptr, $filename );
		}
	}

	/**
	 * Checks direct $wpdb method access.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Variable pointer.
	 * @param string            $filename   Normalized filename.
	 *
	 * @return void
	 */
	private function check_wpdb_method_call( File $phpcs_file, array $tokens, int $ptr, string $filename ): void {
		if ( $this->is_storage_path( $filename ) ) {
			return;
		}

		$operator = $this->next_non_empty( $tokens, $ptr );
		$method   = $this->next_non_empty( $tokens, $operator );

		if ( T_OBJECT_OPERATOR !== $tokens[ $operator ]['code'] || T_STRING !== $tokens[ $method ]['code'] ) {
			return;
		}

		$method_name = strtolower( $tokens[ $method ]['content'] );

		if ( isset( self::WPDB_SQL_METHODS[ $method_name ] ) ) {
			$phpcs_file->addError(
				'Direct SQL through $wpdb is restricted to src/storage/ classes.',
				$method,
				'DirectSqlOutsideStorage'
			);
		}
	}

	/**
	 * Checks direct $GLOBALS['wpdb'] method access.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Variable pointer.
	 * @param string            $filename   Normalized filename.
	 *
	 * @return void
	 */
	private function check_wpdb_global_method_call( File $phpcs_file, array $tokens, int $ptr, string $filename ): void {
		if ( $this->is_storage_path( $filename ) ) {
			return;
		}

		$open_bracket = $this->next_non_empty( $tokens, $ptr );

		if ( '[' !== $tokens[ $open_bracket ]['content'] || ! isset( $tokens[ $open_bracket ]['bracket_closer'] ) ) {
			return;
		}

		$key = $this->raw_tokens( $tokens, $open_bracket + 1, (int) $tokens[ $open_bracket ]['bracket_closer'] - 1 );

		if ( 'wpdb' !== $this->string_literal_value( $key ) ) {
			return;
		}

		$operator = $this->next_non_empty( $tokens, (int) $tokens[ $open_bracket ]['bracket_closer'] );
		$method   = $this->next_non_empty( $tokens, $operator );

		if ( T_OBJECT_OPERATOR !== $tokens[ $operator ]['code'] || T_STRING !== $tokens[ $method ]['code'] ) {
			return;
		}

		$method_name = strtolower( $tokens[ $method ]['content'] );

		if ( isset( self::WPDB_SQL_METHODS[ $method_name ] ) ) {
			$phpcs_file->addError(
				'Direct SQL through $GLOBALS[\'wpdb\'] is restricted to src/storage/ classes.',
				$method,
				'DirectSqlOutsideStorage'
			);
		}
	}

	/**
	 * Checks mutating WP_Filesystem calls.
	 *
	 * @param File                $phpcs_file              The PHPCS file.
	 * @param array<int, array>   $tokens                  PHPCS tokens.
	 * @param int                 $ptr                     Object operator pointer.
	 * @param array<string, true> $wp_filesystem_variables WP_Filesystem variables.
	 *
	 * @return void
	 */
	private function check_wp_filesystem_method_call( File $phpcs_file, array $tokens, int $ptr, array $wp_filesystem_variables ): void {
		$object = $this->previous_non_empty( $tokens, $ptr );

		if ( null === $object || T_VARIABLE !== $tokens[ $object ]['code'] || ! isset( $wp_filesystem_variables[ $tokens[ $object ]['content'] ] ) ) {
			return;
		}

		$method = $this->next_non_empty( $tokens, $ptr );

		if ( T_STRING !== $tokens[ $method ]['code'] ) {
			return;
		}

		$method_name = strtolower( $tokens[ $method ]['content'] );

		if ( isset( self::FORBIDDEN_WP_FILESYSTEM_METHODS[ $method_name ] ) ) {
			$phpcs_file->addError(
				'Runtime code must not mutate files through WP_Filesystem.',
				$method,
				'FilesystemWrite'
			);
		}
	}

	/**
	 * Finds variables that refer to the WordPress filesystem abstraction.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 *
	 * @return array<string, true>
	 */
	private function wp_filesystem_variables( array $tokens ): array {
		$variables = [
			'$wp_filesystem' => true,
		];

		foreach ( $tokens as $ptr => $token ) {
			if ( T_VARIABLE !== $token['code'] ) {
				continue;
			}

			$assignment = $this->next_non_empty( $tokens, (int) $ptr );

			if ( '=' !== $tokens[ $assignment ]['content'] ) {
				continue;
			}

			$new = $this->next_non_empty( $tokens, $assignment );

			if ( T_NEW !== $tokens[ $new ]['code'] ) {
				continue;
			}

			$class = $this->class_name_after_new( $tokens, $new );

			if ( null !== $class && isset( self::WP_FILESYSTEM_CLASSES[ $this->function_name( $tokens[ $class ]['content'] ) ] ) ) {
				$variables[ $token['content'] ] = true;
			}
		}//end foreach

		return $variables;
	}

	/**
	 * Finds the class-name token after a new expression.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $new_ptr New keyword pointer.
	 *
	 * @return int|null
	 */
	private function class_name_after_new( array $tokens, int $new_ptr ): ?int {
		$class = $this->next_non_empty( $tokens, $new_ptr );

		while ( T_NS_SEPARATOR === $tokens[ $class ]['code'] ) {
			$class = $this->next_non_empty( $tokens, $class );
		}

		if ( ! in_array( $tokens[ $class ]['code'], [ T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED, T_NAME_RELATIVE ], true ) ) {
			return null;
		}

		return $class;
	}

	/**
	 * Checks write-mode fopen() calls.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Function-name pointer.
	 * @param int               $open_ptr   Opening parenthesis pointer.
	 *
	 * @return void
	 */
	private function check_fopen_mode( File $phpcs_file, array $tokens, int $ptr, int $open_ptr ): void {
		$args = $this->function_arguments( $tokens, $open_ptr );
		$mode = $this->argument( $args, 'mode', 1 );

		if ( null === $mode ) {
			$phpcs_file->addError(
				'fopen() calls must use an explicit read-only mode.',
				$ptr,
				'FilesystemWrite'
			);
			return;
		}

		$value = $this->string_literal_value( $mode['raw'] );

		if ( null === $value || ! preg_match( '/^r[bt]?$/i', $value ) ) {
			$phpcs_file->addError(
				'fopen() calls must use a read-only mode.',
				$mode['ptr'],
				'FilesystemWrite'
			);
		}
	}

	/**
	 * Checks rewrite flushes.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Function-name pointer.
	 * @param int               $open_ptr   Opening parenthesis pointer.
	 *
	 * @return void
	 */
	private function check_rewrite_flush( File $phpcs_file, array $tokens, int $ptr, int $open_ptr ): void {
		$args = $this->function_arguments( $tokens, $open_ptr );
		$hard = $this->argument( $args, 'hard', 0 );

		if ( null === $hard || ! in_array( strtolower( $this->normalized_expression( $hard['raw'] ) ), [ 'false', '0' ], true ) ) {
			$phpcs_file->addError(
				'flush_rewrite_rules() must pass false so runtime code never writes rewrite files.',
				$ptr,
				'FilesystemWrite'
			);
		}
	}

	/**
	 * Checks plugin-owned option autoload behavior.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Function-name pointer.
	 * @param int               $open_ptr   Opening parenthesis pointer.
	 * @param string            $name       Function name.
	 *
	 * @return void
	 */
	private function check_option_autoload( File $phpcs_file, array $tokens, int $ptr, int $open_ptr, string $name ): void {
		$args         = $this->function_arguments( $tokens, $open_ptr );
		$option       = $this->argument( $args, 'option', 0 );
		$autoload     = $this->argument( $args, 'autoload', 'add_option' === $name ? 3 : 2 );
		$is_owned     = null !== $option && $this->is_plugin_owned_option_expression( $option['raw'] );
		$allows_true  = null !== $option && $this->is_flags_option_expression( $option['raw'] );
		$is_true_like = null !== $autoload && $this->is_true_like_autoload_expression( $autoload['raw'] );

		if ( $is_true_like && ! $allows_true ) {
			$phpcs_file->addError(
				'Plugin options must not autoload; only seograph_flags may use autoload=true.',
				$autoload['ptr'],
				'AutoloadedOption'
			);
			return;
		}

		if ( $is_owned && null === $autoload ) {
			$phpcs_file->addError(
				'Plugin-owned options must pass an explicit autoload value; use false unless writing seograph_flags.',
				$ptr,
				'AutoloadedOption'
			);
		}
	}

	/**
	 * Checks direct redirect calls.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Function-name pointer.
	 * @param int               $open_ptr   Opening parenthesis pointer.
	 * @param string            $filename   Normalized filename.
	 *
	 * @return void
	 */
	private function check_redirect_call( File $phpcs_file, array $tokens, int $ptr, int $open_ptr, string $filename ): void {
		$args       = $this->function_arguments( $tokens, $open_ptr );
		$x_redirect = $this->argument( $args, 'x_redirect_by', 2 );

		if ( ! $this->is_redirect_service_path( $filename ) ) {
			$phpcs_file->addError(
				'Redirects must go through the redirect service so the SEO Graph trace header is always present.',
				$ptr,
				'RedirectOutsideService'
			);
			return;
		}

		if ( null === $x_redirect || ! str_contains( $x_redirect['raw'], 'seo-graph; rule=' ) ) {
			$phpcs_file->addError(
				'Redirect service calls must pass X-Redirect-By with the "seo-graph; rule=" trace value.',
				null !== $x_redirect ? $x_redirect['ptr'] : $ptr,
				'RedirectTraceHeader'
			);
		}
	}

	/**
	 * Checks document-head tag construction outside presenters.
	 *
	 * Raw SEO head-tag templates belong in presenters, whatever the resulting
	 * string is later used for — output, comparison data or search data. The
	 * check reconstructs the expression-local template shape (locally known
	 * literal fragments plus opaque slots for runtime values) and matches the
	 * protected tag families against it, so attribute order, whitespace, case
	 * and quoting cannot hide a template. It is intentionally bounded: it
	 * recognizes statically identifiable shapes and does not evaluate arbitrary
	 * functions or reconstruct runtime-computed HTML.
	 *
	 * @param File              $phpcs_file The PHPCS file.
	 * @param array<int, array> $tokens     PHPCS tokens.
	 * @param int               $ptr        Statement pointer.
	 * @param string            $filename   Normalized filename.
	 *
	 * @return void
	 */
	private function check_head_template_construction( File $phpcs_file, array $tokens, int $ptr, string $filename ): void {
		if ( $this->is_presenter_path( $filename ) ) {
			return;
		}

		$statement_start = $this->statement_start( $tokens, $ptr );
		$end             = $this->statement_end( $tokens, $statement_start );

		$shape = $this->statement_shape( $tokens, $statement_start, $end );

		if ( $shape === '' ) {
			return;
		}

		// The documented standalone sitemap/XSL full-document rendering allowance.
		if ( str_contains( $filename, '/src/sitemaps/' ) && str_contains( $shape, '<html><head><title>' ) ) {
			return;
		}

		foreach ( $this->protected_tag_families( $shape ) as $family ) {
			$phpcs_file->addError(
				sprintf(
					'Raw %1$s tag templates belong to presenters; build them only in src/presenters/ (spec §3.2).',
					$family
				),
				$ptr,
				'HeadOutputOutsidePresenter'
			);
			break;
		}
	}

	/**
	 * Returns whether a token can start a statement that carries string content.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Token pointer.
	 *
	 * @return bool
	 */
	private function is_string_statement( array $tokens, int $ptr ): bool {
		return in_array(
			$tokens[ $ptr ]['code'],
			[
				T_VARIABLE,
				T_STRING,
				T_NAME_FULLY_QUALIFIED,
				T_NAME_QUALIFIED,
				T_NAME_RELATIVE,
				T_CONSTANT_ENCAPSED_STRING,
				T_ECHO,
				T_PRINT,
				T_RETURN,
				T_NEW,
				T_LNUMBER,
				T_CONST,
			],
			true
		);
	}

	/**
	 * Walks back to the first token of the statement that contains the pointer.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Token pointer.
	 *
	 * @return int
	 */
	private function statement_start( array $tokens, int $ptr ): int {
		for ( $i = $ptr; $i >= 0; $i-- ) {
			$content = $tokens[ $i ]['content'];

			if ( in_array( $content, [ ';', '{', '}', '(', ')', '[', '?>' ], true ) ) {
				return $i + 1;
			}

			if ( $this->is_empty_token( $tokens[ $i ]['code'] ) ) {
				continue;
			}
		}

		return 0;
	}

	/**
	 * Rebuilds a statement's template shape: lowercase literal fragments with
	 * quotes removed, whitespace collapsed, and an opaque `<?>` slot wherever a
	 * runtime value or expression boundary sits between fragments. Comments and
	 * whitespace never contribute to the shape.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $start  Statement start pointer.
	 * @param int               $end    Statement end pointer.
	 *
	 * @return string
	 */
	private function statement_shape( array $tokens, int $start, int $end ): string {
		$shape = '';

		for ( $i = $start; $i <= $end; $i++ ) {
			$code = $tokens[ $i ]['code'];

			if ( T_CONSTANT_ENCAPSED_STRING === $code ) {
				$fragment = $this->normalize_fragment( $this->strip_string_quotes( $tokens[ $i ]['content'] ) );

				if ( $fragment !== '' ) {
					$shape .= $fragment;
				}

				continue;
			}

			if ( T_ENCAPSED_AND_WHITESPACE === $code ) {
				// Interpolated values inside a double-quoted string are opaque slots.
				if ( $shape !== '' && $this->fragment_seen_before( $tokens, $i ) ) {
					$shape .= '<??>';
				}

				continue;
			}

			if ( $this->is_empty_token( $code ) ) {
				continue;
			}

			// Any other token between string fragments is an expression boundary;
			// it separates fragments with a slot so two adjacent tags cannot
			// merge into one false-positive shape.
			if ( $shape !== '' && $this->pending_fragment_follows( $tokens, $i, $end ) ) {
				$shape .= '<??>';
			}
		}

		return $shape;
	}

	/**
	 * Returns whether an interpolated value is inside a quoted string, i.e.
	 * directly preceded by a string fragment.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Encapsed pointer.
	 *
	 * @return bool
	 */
	private function fragment_seen_before( array $tokens, int $ptr ): bool {
		for ( $i = $ptr - 1; $i >= 0; $i-- ) {
			$code = $tokens[ $i ]['code'];

			if ( $this->is_empty_token( $code ) ) {
				continue;
			}

			return T_CONSTANT_ENCAPSED_STRING === $code || T_ENCAPSED_AND_WHITESPACE === $code;
		}

		return false;
	}

	/**
	 * Returns whether a later string fragment follows this boundary token within
	 * the same statement, so the boundary separates fragments rather than
	 * trailing the shape.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Boundary token pointer.
	 * @param int               $end    Statement end pointer.
	 *
	 * @return bool
	 */
	private function pending_fragment_follows( array $tokens, int $ptr, int $end ): bool {
		for ( $i = $ptr + 1; $i <= $end; $i++ ) {
			if ( in_array( $tokens[ $i ]['code'], [ T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE ], true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns the protected head-tag families identified in a shape.
	 *
	 * A family matches when the tag start sits at a real tag boundary, its
	 * defining attribute is present, and the tag region carries a closing angle
	 * bracket or an opaque slot — the distinction that keeps a raw tag template
	 * (including one whose value is concatenated from runtime data) flagged
	 * while a partial search needle (no closing bracket, no slot) stays legal.
	 * A bare MIME value such as 'application/ld+json' is data, not a tag: the
	 * JSON-LD family requires the script tag shape around it.
	 *
	 * @param string $shape Normalized statement shape.
	 *
	 * @return array<int, string>
	 */
	private function protected_tag_families( string $shape ): array {
		$families = [];

		foreach ( $this->tag_start_offsets( $shape, 'meta' ) as $offset ) {
			$region = $this->tag_region( $shape, $offset );

			if ( preg_match( '/\b(name|property)\s*=/', $region ) && ( $this->region_has_close( $region ) || str_contains( $region, '<??>' ) ) ) {
				$families[] = 'meta';
				break;
			}
		}

		foreach ( $this->tag_start_offsets( $shape, 'link' ) as $offset ) {
			$region = $this->tag_region( $shape, $offset );

			if ( preg_match( '/\brel\s*=/', $region ) && ( $this->region_has_close( $region ) || str_contains( $region, '<??>' ) ) ) {
				$families[] = 'link';
				break;
			}
		}

		foreach ( $this->tag_start_offsets( $shape, 'script' ) as $offset ) {
			$region = $this->tag_region( $shape, $offset );

			if ( str_contains( $region, 'application/ld+json' ) && ( $this->region_has_close( $region ) || str_contains( $region, '<??>' ) ) ) {
				$families[] = 'JSON-LD script';
				break;
			}
		}

		foreach ( $this->tag_start_offsets( $shape, 'title' ) as $offset ) {
			$region      = $this->tag_region( $shape, $offset );
			$closes      = $this->region_has_close( $region ) || str_contains( $region, '<??>' );
			$has_content = str_contains( substr( $shape, $offset ), '</title' ) || str_contains( $shape, '<??>' );

			if ( $closes && $has_content ) {
				$families[] = 'title';
				break;
			}
		}

		return $families;
	}

	/**
	 * Finds boundary-qualified occurrences of a tag start in a shape.
	 *
	 * @param string $shape Shape text.
	 * @param string $tag   Tag name (lowercase).
	 *
	 * @return array<int, int>
	 */
	private function tag_start_offsets( string $shape, string $tag ): array {
		$offsets = [];
		$needle  = '<' . $tag;
		$start   = 0;

		while ( false !== ( $pos = strpos( $shape, $needle, $start ) ) ) {
			$after = $shape[ $pos + strlen( $needle ) ] ?? '';

			if ( ( '' === $after || ctype_space( $after ) || '>' === $after ) && $this->is_tag_boundary( $shape, $pos ) ) {
				$offsets[] = $pos;
			}

			$start = $pos + 1;
		}

		return $offsets;
	}

	/**
	 * Returns whether a tag start at the offset sits at a real markup boundary.
	 *
	 * @param string $shape  Shape text.
	 * @param int    $offset Tag start offset.
	 *
	 * @return bool
	 */
	private function is_tag_boundary( string $shape, int $offset ): bool {
		if ( 0 === $offset ) {
			return true;
		}

		return false !== strpos( self::TAG_BOUNDARY_PRECEDING, $shape[ $offset - 1 ] );
	}

	/**
	 * Returns the tag region: from the tag start to its first closing bracket
	 * (inclusive), or to the shape end when the tag never closes.
	 *
	 * @param string $shape Shape text.
	 * @param int    $start Tag start offset.
	 *
	 * @return string
	 */
	private function tag_region( string $shape, int $start ): string {
		$close = strpos( $shape, '>', $start );

		return null === $close ? substr( $shape, $start ) : substr( $shape, $start, (int) $close - $start + 1 );
	}

	/**
	 * Returns whether a tag region carries its closing bracket.
	 *
	 * @param string $region Tag region text.
	 *
	 * @return bool
	 */
	private function region_has_close( string $region ): bool {
		return str_ends_with( $region, '>' );
	}

	/**
	 * Normalizes a string fragment: lowercase, quotes removed, whitespace collapsed.
	 *
	 * @param string $fragment Fragment text.
	 *
	 * @return string
	 */
	private function normalize_fragment( string $fragment ): string {
		$fragment = str_replace( [ '"', "'" ], '', strtolower( $fragment ) );

		return (string) preg_replace( '/\s+/', ' ', trim( $fragment ) );
	}

	/**
	 * Strips the outer quotes of a single-quoted or double-quoted literal.
	 *
	 * @param string $content Token content.
	 *
	 * @return string
	 */
	private function strip_string_quotes( string $content ): string {
		$first = $content[0] ?? '';

		if ( in_array( $first, [ '"', "'" ], true ) && substr( $content, -1 ) === $first && strlen( $content ) >= 2 ) {
			return substr( $content, 1, -1 );
		}

		return $content;
	}

	/**
	 * Determines whether the token is a direct function call.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Token pointer.
	 *
	 * @return bool
	 */
	private function is_function_call( array $tokens, int $ptr ): bool {
		if ( ! in_array( $tokens[ $ptr ]['code'], [ T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED, T_NAME_RELATIVE ], true ) ) {
			return false;
		}

		$next = $this->next_non_empty( $tokens, $ptr );

		if ( '(' !== $tokens[ $next ]['content'] ) {
			return false;
		}

		$previous = $this->previous_non_empty( $tokens, $ptr );

		while ( null !== $previous && in_array( $tokens[ $previous ]['code'], [ T_NS_SEPARATOR ], true ) ) {
			$previous = $this->previous_non_empty( $tokens, $previous );
		}

		if ( null === $previous ) {
			return true;
		}

		return ! in_array(
			$tokens[ $previous ]['code'],
			[ T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_OBJECT_OPERATOR ],
			true
		);
	}

	/**
	 * Extracts function arguments from an opening parenthesis.
	 *
	 * @param array<int, array> $tokens   PHPCS tokens.
	 * @param int               $open_ptr Opening parenthesis pointer.
	 *
	 * @return array<int, array{name: string|null, raw: string, ptr: int}>
	 */
	private function function_arguments( array $tokens, int $open_ptr ): array {
		$close_ptr = (int) $tokens[ $open_ptr ]['parenthesis_closer'];
		$args      = [];
		$depth     = 0;
		$start     = $this->next_non_empty( $tokens, $open_ptr );

		if ( $start >= $close_ptr ) {
			return [];
		}

		for ( $i = $open_ptr + 1; $i < $close_ptr; $i++ ) {
			$content = $tokens[ $i ]['content'];

			if ( in_array( $content, [ '(', '[', '{' ], true ) ) {
				++$depth;
			} elseif ( in_array( $content, [ ')', ']', '}' ], true ) ) {
				--$depth;
			} elseif ( ',' === $content && 0 === $depth ) {
				$args[] = $this->argument_from_range( $tokens, $start, $i - 1 );
				$start  = $this->next_non_empty( $tokens, $i );
			}
		}

		if ( $start < $close_ptr ) {
			$args[] = $this->argument_from_range( $tokens, $start, $close_ptr - 1 );
		}

		return $args;
	}

	/**
	 * Returns a normalized argument from a token range.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $start  Start pointer.
	 * @param int               $end    End pointer.
	 *
	 * @return array{name: string|null, raw: string, ptr: int}
	 */
	private function argument_from_range( array $tokens, int $start, int $end ): array {
		$raw = $this->raw_tokens( $tokens, $start, $end );

		$name = null;

		if ( preg_match( '/^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:/', $raw, $matches ) ) {
			$name = strtolower( $matches[1] );
			$raw  = preg_replace( '/^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:/', '', $raw, 1 ) ?? $raw;
		}

		return [
			'name' => $name,
			'ptr'  => $start,
			'raw'  => trim( $raw ),
		];
	}

	/**
	 * Returns the raw token content for a range.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $start  Start pointer.
	 * @param int               $end    End pointer.
	 *
	 * @return string
	 */
	private function raw_tokens( array $tokens, int $start, int $end ): string {
		$raw = '';

		for ( $i = $start; $i <= $end; $i++ ) {
			$raw .= $tokens[ $i ]['content'];
		}

		return $raw;
	}

	/**
	 * Finds a positional or named argument.
	 *
	 * @param array<int, array{name: string|null, raw: string, ptr: int}> $args     Function arguments.
	 * @param string                                                      $name     Named argument.
	 * @param int                                                         $position Positional index.
	 *
	 * @return array{name: string|null, raw: string, ptr: int}|null
	 */
	private function argument( array $args, string $name, int $position ): ?array {
		foreach ( $args as $arg ) {
			if ( $name === $arg['name'] ) {
				return $arg;
			}
		}

		return $args[ $position ] ?? null;
	}

	/**
	 * Gets the statement end pointer.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Statement pointer.
	 *
	 * @return int
	 */
	private function statement_end( array $tokens, int $ptr ): int {
		$count = count( $tokens );

		for ( $i = $ptr; $i < $count; $i++ ) {
			if ( ';' === $tokens[ $i ]['content'] || '?>' === $tokens[ $i ]['content'] ) {
				return $i;
			}
		}

		return $count - 1;
	}

	/**
	 * Returns the next non-empty token pointer.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Token pointer.
	 *
	 * @return int
	 */
	private function next_non_empty( array $tokens, int $ptr ): int {
		$count = count( $tokens );

		for ( $i = $ptr + 1; $i < $count; $i++ ) {
			if ( ! $this->is_empty_token( $tokens[ $i ]['code'] ) ) {
				return $i;
			}
		}

		return $ptr;
	}

	/**
	 * Returns the previous non-empty token pointer.
	 *
	 * @param array<int, array> $tokens PHPCS tokens.
	 * @param int               $ptr    Token pointer.
	 *
	 * @return int|null
	 */
	private function previous_non_empty( array $tokens, int $ptr ): ?int {
		for ( $i = $ptr - 1; $i >= 0; $i-- ) {
			if ( ! $this->is_empty_token( $tokens[ $i ]['code'] ) ) {
				return $i;
			}
		}

		return null;
	}

	/**
	 * Returns whether a token code is whitespace or comment.
	 *
	 * @param int|string $code Token code.
	 *
	 * @return bool
	 */
	private function is_empty_token( $code ): bool {
		return in_array(
			$code,
			[
				T_COMMENT,
				T_DOC_COMMENT,
				T_DOC_COMMENT_CLOSE_TAG,
				T_DOC_COMMENT_OPEN_TAG,
				T_DOC_COMMENT_STAR,
				T_DOC_COMMENT_STRING,
				T_WHITESPACE,
			],
			true
		);
	}

	/**
	 * Normalizes a function name token.
	 *
	 * @param string $name Function token content.
	 *
	 * @return string
	 */
	private function function_name( string $name ): string {
		return strtolower( ltrim( $name, '\\' ) );
	}

	/**
	 * Normalizes expression text.
	 *
	 * @param string $expression Expression text.
	 *
	 * @return string
	 */
	private function normalized_expression( string $expression ): string {
		return strtolower( preg_replace( '/\s+/', '', trim( $expression ) ) ?? trim( $expression ) );
	}

	/**
	 * Returns a string literal value when the expression is a single literal.
	 *
	 * @param string $expression Expression text.
	 *
	 * @return string|null
	 */
	private function string_literal_value( string $expression ): ?string {
		$expression = trim( $expression );
		$quote      = $expression[0] ?? '';

		if ( ! in_array( $quote, [ '"', "'" ], true ) || substr( $expression, -1 ) !== $quote ) {
			return null;
		}

		return stripcslashes( substr( $expression, 1, -1 ) );
	}

	/**
	 * Returns whether an expression is a plugin-owned option identifier.
	 *
	 * @param string $expression Option expression.
	 *
	 * @return bool
	 */
	private function is_plugin_owned_option_expression( string $expression ): bool {
		$value = $this->string_literal_value( $expression );

		if ( null !== $value && str_starts_with( $value, 'seograph_' ) ) {
			return true;
		}

		return (bool) preg_match( '/(?:^|[\\\\:>$])(?:[A-Z_]+_)?OPTION(?:$|[^A-Za-z0-9_])/', $expression );
	}

	/**
	 * Returns whether an expression targets the sole intentionally autoloaded option.
	 *
	 * @param string $expression Option expression.
	 *
	 * @return bool
	 */
	private function is_flags_option_expression( string $expression ): bool {
		$value = $this->string_literal_value( $expression );

		if ( 'seograph_flags' === $value ) {
			return true;
		}

		return str_contains( $expression, 'FLAGS_OPTION' );
	}

	/**
	 * Returns whether an autoload expression requests autoloading.
	 *
	 * @param string $expression Autoload expression.
	 *
	 * @return bool
	 */
	private function is_true_like_autoload_expression( string $expression ): bool {
		$normalized = $this->normalized_expression( $expression );
		$value      = $this->string_literal_value( $expression );

		return 'true' === $normalized || '1' === $normalized || in_array( strtolower( (string) $value ), [ 'yes', 'on', 'auto-on' ], true );
	}

	/**
	 * Returns whether a file path should be scanned by this architecture sniff.
	 *
	 * @param string $filename Normalized filename.
	 *
	 * @return bool
	 */
	private function should_scan( string $filename ): bool {
		foreach ( self::EXCLUDED_PATH_PARTS as $part ) {
			if ( str_contains( $filename, $part ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Returns whether a path is part of the storage layer.
	 *
	 * @param string $filename Normalized filename.
	 *
	 * @return bool
	 */
	private function is_storage_path( string $filename ): bool {
		return str_contains( $filename, '/src/storage/' );
	}

	/**
	 * Returns whether a path is part of the presenter layer.
	 *
	 * @param string $filename Normalized filename.
	 *
	 * @return bool
	 */
	private function is_presenter_path( string $filename ): bool {
		return str_contains( $filename, '/src/presenters/' );
	}

	/**
	 * Returns whether a path is the central redirect service.
	 *
	 * @param string $filename Normalized filename.
	 *
	 * @return bool
	 */
	private function is_redirect_service_path( string $filename ): bool {
		return str_ends_with( $filename, '/src/redirects/class-redirect-service.php' );
	}

	/**
	 * Normalizes a filesystem path.
	 *
	 * @param string $path Raw path.
	 *
	 * @return string
	 */
	private function normalize_path( string $path ): string {
		return str_replace( '\\', '/', $path );
	}
}
