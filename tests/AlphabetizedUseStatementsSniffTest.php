<?php
/**
 * Alphabetized-use-statement sniff tests.
 *
 * @package SeoGraphCS
 */

use PHPUnit\Framework\TestCase;

/**
 * Verifies that the standard orders namespace imports alphabetically.
 */
final class AlphabetizedUseStatementsSniffTest extends TestCase {

	private string $fixture_root;

	protected function setUp(): void {
		$this->fixture_root = sys_get_temp_dir() . '/seographcs-' . bin2hex( random_bytes( 8 ) );
		mkdir( $this->fixture_root . '/src', 0700, true );
	}

	protected function tearDown(): void {
		$this->remove_directory( $this->fixture_root );
	}

	public function test_reversed_imports_fail_with_the_owning_convention_diagnostic(): void {
		file_put_contents(
			$this->fixture_root . '/src/reversed.php',
			"<?php\n\nnamespace SeoGraph\\Templating;\n\nuse SeoGraph\\Templating\\Template_Renderer;\nuse SeoGraph\\Storage\\Options;\n\nclass Reversed {\n}\n"
		);

		$source = $this->convention_sources( 'src' );
		$this->assertContains( 'SeoGraphCS.Conventions.AlphabetizedUseStatements.Unsorted', $source );
	}

	public function test_alphabetized_imports_pass(): void {
		file_put_contents(
			$this->fixture_root . '/src/ordered.php',
			"<?php\n\nnamespace SeoGraph\\Templating;\n\nuse SeoGraph\\Storage\\Options;\nuse SeoGraph\\Templating\\Template_Renderer;\n\nclass Ordered {\n}\n"
		);

		$this->assertSame( [], $this->convention_sources( 'src' ) );
	}

	public function test_grouped_imports_order_by_their_first_expanded_name(): void {
		file_put_contents(
			$this->fixture_root . '/src/grouped-reversed.php',
			"<?php\n\nnamespace SeoGraph;\n\nuse SeoGraph\\Templating\\{Template_Renderer, Template_Source};\nuse SeoGraph\\Storage\\Options;\n\nclass GroupedReversed {\n}\n"
		);

		$source = $this->convention_sources( 'src' );
		$this->assertContains( 'SeoGraphCS.Conventions.AlphabetizedUseStatements.Unsorted', $source );
	}

	public function test_trait_use_statements_are_ignored(): void {
		file_put_contents(
			$this->fixture_root . '/src/trait-use.php',
			"<?php\n\nnamespace SeoGraph;\n\nuse SeoGraph\\Alpha\\Alpha_Trait;\nuse SeoGraph\\Zeta\\Zeta_Trait;\n\nclass Host {\n\tuse Zeta_Trait, Alpha_Trait;\n}\n"
		);

		$this->assertSame( [], $this->convention_sources( 'src' ) );
	}

	public function test_closure_variable_captures_are_not_imports(): void {
		file_put_contents(
			$this->fixture_root . '/src/closure-capture.php',
			"<?php\n\nnamespace SeoGraph;\n\nuse SeoGraph\\Alpha\\Alpha_Helper;\nuse SeoGraph\\Zeta\\Zeta_Helper;\n\nfunction factory() {\n\t\$name = 'x';\n\treturn function ( string \$input ) use ( \$name, \$input ) : string {\n\t\treturn \$name . \$input;\n\t};\n}\n"
		);

		$this->assertSame( [], $this->convention_sources( 'src' ) );
	}

	public function test_function_and_const_imports_are_outside_the_convention(): void {
		file_put_contents(
			$this->fixture_root . '/src/function-imports.php',
			"<?php\n\nnamespace SeoGraph;\n\nuse function Zeta\\zeta_helper;\nuse function Alpha\\alpha_helper;\n"
		);

		$this->assertSame( [], $this->convention_sources( 'src' ) );
	}

	public function test_fixer_orders_a_contiguous_block_alphabetically(): void {
		file_put_contents(
			$this->fixture_root . '/src/fix-me.php',
			"<?php\n\nnamespace SeoGraph;\n\nuse SeoGraph\\Templating\\Template_Renderer;\nuse SeoGraph\\Storage\\Options;\n\nclass FixMe {\n}\n"
		);

		$command = sprintf(
			'%s --standard=SeoGraphCS --extensions=php --report=json -d memory_limit=2G -- %s',
			escapeshellarg( dirname( __DIR__ ) . '/vendor/bin/phpcbf' ),
			escapeshellarg( $this->fixture_root . '/src/fix-me.php' )
		);

		exec( $command, $output, $code );
		// phpcbf exits 1 when the file retains any unfixable error (the fixture
		// intentionally lacks a WPCS file header); only a crash (2) is a failure.
		$this->assertLessThan( 2, (int) $code, implode( "\n", $output ) );

		$fixed = file_get_contents( $this->fixture_root . '/src/fix-me.php' );
		$this->assertNotFalse( $fixed );
		$renderer_at = strpos( $fixed, 'use SeoGraph\\Templating\\Template_Renderer;' );
		$options_at  = strpos( $fixed, 'use SeoGraph\\Storage\\Options;' );
		$this->assertNotFalse( $options_at );
		$this->assertNotFalse( $renderer_at );
		$this->assertLessThan( $renderer_at, $options_at, 'The Options import must be ordered before the Template_Renderer import.' );
	}

	/**
	 * Runs phpcs over a fixture subdirectory and collects this sniff's sources.
	 *
	 * @return array<int,string>
	 */
	private function convention_sources( string $path ): array {
		$command = sprintf(
			'%s --standard=SeoGraphCS --extensions=php --report=json %s',
			escapeshellarg( dirname( __DIR__ ) . '/vendor/bin/phpcs' ),
			escapeshellarg( $this->fixture_root . '/' . $path )
		);

		exec( $command, $output );
		$result  = json_decode( implode( "\n", $output ), true );
		$sources = [];
		foreach ( (array) $result['files'] as $messages ) {
			foreach ( (array) $messages['messages'] as $message ) {
				if ( str_starts_with( $message['source'], 'SeoGraphCS.Conventions.AlphabetizedUseStatements.' ) ) {
					$sources[] = $message['source'];
				}
			}
		}

		return $sources;
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
