<?php
/**
 * Storage-boundary SQL extension tests.
 *
 * Runs the installed PHPStan against inert fixture files with the real
 * WordPress stubs, proving the extension resolves aliases of the real
 * global (direct, variable and array-held), honors the storage boundary,
 * and leaves unrelated objects valid.
 *
 * @package SeoGraphCS
 */

use PHPUnit\Framework\TestCase;

/**
 * Verifies the PHPStan direct-SQL boundary extension.
 */
final class StorageBoundarySqlExtensionTest extends TestCase {

	private string $fixture_root;

	protected function setUp(): void {
		// The fixture must live inside the package tree: PHPStan discovers the
		// project autoloader from the analyzed paths, and the extension class
		// only autoloades through the package's vendor/autoload.php.
		$this->fixture_root = dirname( __DIR__ ) . '/.test-fixtures/sql-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->fixture_root . '/src/frontend', 0700, true );
		mkdir( $this->fixture_root . '/src/storage', 0700, true );
	}

	protected function tearDown(): void {
		$this->remove_directory( $this->fixture_root );
	}

	public function test_sql_methods_on_wpdb_and_its_subclasses_are_rejected_outside_the_boundary(): void {
		file_put_contents(
			$this->fixture_root . '/src/frontend/class-bad.php',
			'<?php
// The @var annotation is the standard way the real WordPress stubs make the
// global resolvable; it must not be needed for the typed cases below.
class seograph_bad_sql {
	public function direct(): void {
		global $wpdb;
		/** @var \wpdb $wpdb */
		$wpdb->query( "SELECT 1" );
	}
	public function aliased(): void {
		global $wpdb;
		/** @var \wpdb $wpdb */
		$db = $wpdb;
		$db->get_var( "SELECT 2" );
	}
	public function array_held(): void {
		global $wpdb;
		/** @var \wpdb $wpdb */
		$databases = [ $wpdb ];
		$databases[0]->get_row( "SELECT 3" );
	}
	public function subclass(): void {
		$db = new class( "user", "pass", "db", "localhost" ) extends \wpdb {};
		$db->prepare( "SELECT 4" );
	}
	public function harmless( seograph_sql_repository $repository ): void {
		$repository->query( "SELECT 5" );
	}
}
class seograph_sql_repository {
	public function query( string $sql ): void {}
}
'
		);
		file_put_contents(
			$this->fixture_root . '/src/storage/class-ok.php',
			'<?php
class seograph_storage_sql {
	public function run(): void {
		global $wpdb;
		/** @var \wpdb $wpdb */
		$wpdb->query( "SELECT 1" );
		$wpdb->get_results( "SELECT 2" );
	}
}
'
		);

		$config = $this->fixture_root . '/phpstan.neon';
		file_put_contents(
			$config,
			"parameters:\n"
			. "    level: 1\n"
			. "    parallel:\n"
			. "        maximumNumberOfProcesses: 1\n"
			. "    paths:\n"
			. "        - {$this->fixture_root}/src\n"
			. "    scanFiles:\n"
			. "        - " . dirname( __DIR__ ) . "/vendor/php-stubs/wordpress-stubs/wordpress-stubs.php\n"
			. "services:\n"
			. "    -\n"
			. "        class: SeoGraphCS\\PhpStan\\StorageBoundarySqlExtension\n"
			. "        tags:\n"
			. "            - phpstan.restrictedMethodUsageExtension\n"
			. "    -\n"
			. "        class: PHPStan\\Rules\\RestrictedUsage\\RestrictedMethodUsageRule\n"
			. "        tags:\n"
			. "            - phpstan.rules\n"
			);

		$result = $this->run_phpstan( $config );
		$bad    = $this->messages_for( $result, 'src/frontend/class-bad.php' );
		$ok     = $this->messages_for( $result, 'src/storage/class-ok.php' );

		$this->assertSame( 4, count( $bad ), implode( "\n", $bad ) );
		$this->assertSame( [], $ok );
	}

	/**
	 * @param string $config Configuration file path.
	 *
	 * @return array<string,mixed>
	 */
	private function run_phpstan( string $config ): array {
		$command = sprintf(
			'%s analyse --configuration=%s --no-progress --error-format=json --memory-limit=1G',
			escapeshellarg( dirname( __DIR__ ) . '/vendor/bin/phpstan' ),
			escapeshellarg( $config )
		);

		exec( $command, $output, $exit_code );
		$this->assertSame( 1, $exit_code, 'the fixture must produce analysis errors' );

		$result = json_decode( implode( "\n", $output ), true );
		$this->assertIsArray( $result, implode( "\n", $output ) );

		return $result;
	}

	/**
	 * @param array<string,mixed> $result PHPStan JSON report.
	 *
	 * @return array<int,string>
	 */
	private function messages_for( array $result, string $file ): array {
		$messages = [];
		foreach ( $result['files'] as $path => $entry ) {
			if ( ! str_ends_with( $path, $file ) ) {
				continue;
			}
			foreach ( $entry['messages'] as $message ) {
				$messages[] = $message['message'];
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
