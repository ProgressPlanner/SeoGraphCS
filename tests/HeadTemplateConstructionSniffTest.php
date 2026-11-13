<?php
/**
 * Head-template construction sniff tests.
 *
 * Raw SEO head-tag templates belong to presenters (spec §3.2). These tests
 * pin the expression-local shape check: which constructions are rejected at
 * their source, and which legitimate data, inspection, and rendering uses
 * stay allowed.
 *
 * @package SeoGraphCS
 */

use PHPUnit\Framework\TestCase;

/**
 * Verifies the presenter-owned head-template construction rule.
 */
final class HeadTemplateConstructionSniffTest extends TestCase {

	private string $fixture_root;

	protected function setUp(): void {
		$this->fixture_root = sys_get_temp_dir() . '/seographcs-head-' . bin2hex( random_bytes( 8 ) );
		mkdir( $this->fixture_root . '/src', 0700, true );
	}

	protected function tearDown(): void {
		$this->remove_directory( $this->fixture_root );
	}

	public function test_prebuilt_meta_tag_with_runtime_content_value_is_rejected_at_its_source(): void {
		$this->write_fixture(
			'src/analysis/class-meta-builder.php',
			"<?php\nfunction seograph_meta_from_runtime( \$description ): string {\n\t\$tag = '<meta name=\"description\" content=\"' . esc_attr( \$description ) . '\" />';\n\treturn \$tag;\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-meta-builder.php' );
		$this->assertContains( 'SeoGraphCS.Architecture.InvariantBoundaries.HeadOutputOutsidePresenter', $messages );
	}

	public function test_sprintf_and_interpolation_bypasses_are_rejected(): void {
		$this->write_fixture(
			'src/analysis/class-sprintf-bypass.php',
			"<?php\nfunction seograph_sprintf_meta( \$robots ): string {\n\treturn sprintf( '<meta name=\"robots\" content=\"%s\" />', \$robots );\n}\nfunction seograph_interpolated_meta( \$robots ): string {\n\treturn \"<meta name=robots content=\$robots />\";\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-sprintf-bypass.php' );
		$this->assertGreaterThanOrEqual( 2, count( $messages ) );
	}

	public function test_tag_family_variants_do_not_hide_the_template(): void {
		$this->write_fixture(
			'src/analysis/class-variants.php',
			"<?php\nfunction seograph_link_template( \$href ): string {\n\treturn '<LINK  REL=\"canonical\" href=\"' . \$href . '\">';\n}\nfunction seograph_property_template( \$value ): string {\n\treturn '<meta property=og:image content=' . \$value . ' />>';\n}\nfunction seograph_title_template( \$title ): string {\n\treturn '<title>' . esc_html( \$title ) . '</title>';\n}\nfunction seograph_json_ld( \$graph ): string {\n\treturn '<script type=\"application/ld+json\">' . \$graph . '</script>';\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-variants.php' );
		$this->assertGreaterThanOrEqual( 4, count( $messages ) );
	}

	public function test_complete_raw_tag_used_as_comparison_data_is_rejected(): void {
		$this->write_fixture(
			'src/analysis/class-comparison.php',
			"<?php\nfunction seograph_compare( \$head ): bool {\n\t\$known = [ '<meta name=\"robots\" content=\"noindex\" />' ];\n\treturn in_array( \$head, \$known, true );\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-comparison.php' );
		$this->assertContains( 'SeoGraphCS.Architecture.InvariantBoundaries.HeadOutputOutsidePresenter', $messages );
	}

	public function test_mime_data_is_not_head_markup(): void {
		$this->write_fixture(
			'src/rest/class-media-type.php',
			"<?php\nfunction seograph_media_type(): string {\n\treturn 'application/ld+json';\n}\nfunction seograph_header( \$type ): void {\n\theaders( \$type . '; charset=UTF-8' );\n}\n"
		);

		$messages = $this->architecture_messages( 'src/rest/class-media-type.php' );
		$this->assertSame( [], $messages );
	}

	public function test_inspection_and_parsing_patterns_are_allowed(): void {
		$this->write_fixture(
			'src/analysis/class-inspection.php',
			"<?php\nfunction seograph_title_pattern(): string {\n\treturn '#<(svg|script|template|style)(?=[\\s>/])[^>]*>.*?</\\1\\s*>(*SKIP)(*FAIL)|<title(?=[\\s>/])[^>]*>.*?</title\\s*>#is';\n}\nfunction seograph_selectors(): array {\n\treturn [ 'meta[property=\"og:image\"]', 'meta[name=robots]' ];\n}\nfunction seograph_escaped_example(): string {\n\treturn '&lt;meta name=\"robots\"&gt; is an example of a meta tag.';\n}\nfunction seograph_charset_scaffold(): string {\n\t\$doc = '<meta charset=\"utf-8\">';\n	return \$doc;\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-inspection.php' );
		$this->assertSame( [], $messages );
	}

	public function test_boolean_controls_with_permitted_input_are_not_flagged(): void {
		$this->write_fixture(
			'src/analysis/class-boolean-control.php',
			"<?php\nfunction seograph_has_robots_meta( \$head ): bool {\n\t\$needle = '<meta name=\"robots\"';\n\t\$found  = str_contains( \$head, \$needle );\n\treturn \$found;\n}\n"
		);

		$messages = $this->architecture_messages( 'src/analysis/class-boolean-control.php' );
		$this->assertSame( [], $messages );
	}

	public function test_presenters_own_their_templates(): void {
		$this->write_fixture(
			'src/presenters/class-description-presenter.php',
			"<?php\nfunction seograph_presenter_meta( \$description ): string {\n\t\$tag = '<meta name=\"description\" content=\"' . esc_attr( \$description ) . '\" />';\n\techo \$tag;\n\treturn \$tag;\n}\n"
		);

		$messages = $this->architecture_messages( 'src/presenters/class-description-presenter.php' );
		$this->assertSame( [], $messages );
	}

	public function test_sitemap_full_document_rendering_allowance_is_scoped(): void {
		$this->write_fixture(
			'src/sitemaps/class-sitemap-renderer.php',
			"<?php\nfunction seograph_sitemap_html(): string {\n\treturn '<html><head><title>XML Sitemap</title></head><body></body></html>';\n}\n"
		);
		$this->write_fixture(
			'src/frontend/class-feed-robot.php',
			"<?php\nfunction seograph_feed_html(): string {\n\treturn '<html><head><title>Feed</title></head><body></body></html>';\n}\n"
		);

		$this->assertSame( [], $this->architecture_messages( 'src/sitemaps/class-sitemap-renderer.php' ) );

		$frontend = $this->architecture_messages( 'src/frontend/class-feed-robot.php' );
		$this->assertContains( 'SeoGraphCS.Architecture.InvariantBoundaries.HeadOutputOutsidePresenter', $frontend );
	}

	/**
	 * Writes a fixture file.
	 *
	 * @param string $relative_path Path inside the fixture root.
	 * @param string $contents      File contents.
	 *
	 * @return void
	 */
	private function write_fixture( string $relative_path, string $contents ): void {
		$path = $this->fixture_root . '/' . $relative_path;
		mkdir( dirname( $path ), 0700, true );
		file_put_contents( $path, $contents );
	}

	/**
	 * Runs the standard over the fixture root and returns the architecture
	 * messages for one fixture file as a line-keyed list.
	 *
	 * @param string $relative_path Fixture file inside the root.
	 *
	 * @return array<int, string>
	 */
	private function architecture_messages( string $relative_path ): array {
		$command = sprintf(
			'%s --standard=SeoGraphCS --extensions=php --report=json %s',
			escapeshellarg( dirname( __DIR__ ) . '/vendor/bin/phpcs' ),
			escapeshellarg( $this->fixture_root . '/' . $relative_path )
		);

		exec( $command, $output );
		$result = json_decode( implode( "\n", $output ), true );
		$this->assertIsArray( $result );

		$messages = [];
		foreach ( $result['files'] as $file ) {
			foreach ( $file['messages'] as $message ) {
				if ( str_starts_with( $message['source'], 'SeoGraphCS.Architecture.InvariantBoundaries.' ) ) {
					$messages[] = $message['source'];
				}
			}
		}

		return $messages;
	}

	private function remove_directory( string $directory ): void {
		if ( ! is_dir( $directory ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $directory, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $iterator as $item ) {
			$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
		}
		rmdir( $directory );
	}
}
