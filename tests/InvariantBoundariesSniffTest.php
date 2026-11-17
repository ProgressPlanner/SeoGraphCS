<?php
/**
 * Architecture-boundary sniff tests.
 *
 * @package SeoGraphCS
 */

use PHPUnit\Framework\TestCase;

/**
 * Verifies that the public standard executes its project-specific sniff.
 */
final class InvariantBoundariesSniffTest extends TestCase {

	private string $fixture_root;

	protected function setUp(): void {
		$this->fixture_root = sys_get_temp_dir() . '/seographcs-' . bin2hex( random_bytes( 8 ) );
		mkdir( $this->fixture_root . '/src/frontend', 0700, true );
	}

	protected function tearDown(): void {
		$this->remove_directory( $this->fixture_root );
	}

	public function test_standard_rejects_architecture_violations(): void {
		file_put_contents(
			$this->fixture_root . '/src/frontend/class-invalid.php',
			"<?php\nfunction seograph_invalid_runtime(): void {\n\tfile_put_contents( __DIR__ . '/output.txt', 'bad' );\n\twp_redirect( '/target' );\n}\n"
		);

		$result  = $this->run_phpcs();
		$sources = array_column( $result['files'][ array_key_first( $result['files'] ) ]['messages'], 'source' );

		$this->assertContains( 'SeoGraphCS.Architecture.InvariantBoundaries.FilesystemWrite', $sources );
		$this->assertContains( 'SeoGraphCS.Architecture.InvariantBoundaries.RedirectOutsideService', $sources );
	}

	public function test_standard_allows_owned_architecture_boundaries(): void {
		mkdir( $this->fixture_root . '/src/redirects', 0700, true );
		file_put_contents(
			$this->fixture_root . '/src/redirects/class-redirect-service.php',
			"<?php\nfunction seograph_redirect_service( string \$target ): void {\n\twp_redirect( \$target, 302, 'verso; rule=1' );\n}\n"
		);

		$result = $this->run_phpcs();
		$this->assertSame(
			[],
			array_values(
				array_filter(
					array_column( $result['files'][ $this->fixture_root . '/src/redirects/class-redirect-service.php' ]['messages'] ?? [], 'source' ),
					static fn ( string $source ): bool => str_starts_with( $source, 'SeoGraphCS.Architecture.InvariantBoundaries.' )
				)
			)
		);
	}

	/** @return array<string,mixed> */
	private function run_phpcs(): array {
		$command = sprintf(
			'%s --standard=SeoGraphCS --extensions=php --report=json %s',
			escapeshellarg( dirname( __DIR__ ) . '/vendor/bin/phpcs' ),
			escapeshellarg( $this->fixture_root . '/src' )
		);

		exec( $command, $output );
		$result = json_decode( implode( "\n", $output ), true );
		$this->assertIsArray( $result );

		return $result;
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
