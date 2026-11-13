<?php
/**
 * Storage-boundary SQL check tests.
 *
 * Runs the installed PHPStan against inert fixture files with the real
 * WordPress stubs, proving that the type-driven extension and the
 * statement-level rule together reject direct SQL outside the storage
 * boundary — including aliases and array-held copies, with or without the
 * global's type being resolvable — while the boundary itself and unrelated
 * objects stay valid.
 *
 * @package SeoGraphCS
 */

use PHPUnit\Framework\TestCase;

/**
 * Verifies the PHPStan direct-SQL boundary extension and rule.
 */
final class StorageBoundarySqlExtensionTest extends TestCase {

	private string $fixture_root;

	protected function setUp(): void {
		// The fixture must live inside the package tree: PHPStan discovers the
		// project autoloader from the analyzed paths, and the extension class
		// only autoloads through the package's vendor/autoload.php.
		$this->fixture_root = dirname( __DIR__ ) . '/.test-fixtures/sql-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->fixture_root . '/src/frontend', 0700, true );
		mkdir( $this->fixture_root . '/src/storage', 0700, true );
	}

	protected function tearDown(): void {
		$this->remove_directory( $this->fixture_root );
	}

	public function test_typed_wpdb_sql_is_rejected_outside_the_boundary(): void {
		file_put_contents(
			$this->fixture_root . '/src/frontend/class-bad-typed.php',
			'<?php
// The @var annotation is the standard way the real WordPress stubs make the
// global resolvable; the type-driven extension must fire for these shapes.
class seograph_bad_sql_typed {
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

		$config = $this->write_config();
		$result = $this->run_phpstan( $config );

		$bad = $this->messages_for( $result, 'src/frontend/class-bad-typed.php' );
		$this->assertSame( 4, count( $bad ), implode( "\n", $bad ) );
		foreach ( $bad as $message ) {
			$this->assertStringContainsString( 'restricted to the storage layer boundary', $message );
		}
	}

	public function test_bare_unannotated_wpdb_global_is_rejected_outside_the_boundary(): void {
		file_put_contents(
			$this->fixture_root . '/src/frontend/class-bad-bare.php',
			'<?php
// No @var annotation: the analysis run resolves the global to mixed, so the
// statement-level rule must catch these shapes by scope tracking.
class seograph_bad_sql_bare {
	public function direct(): void {
		global $wpdb;
		$wpdb->query( "SELECT 1" );
	}
	public function aliased(): void {
		global $wpdb;
		$db = $wpdb;
		$db->get_var( "SELECT 2" );
	}
	public function array_held(): void {
		global $wpdb;
		$databases = [ $wpdb ];
		$databases[0]->get_row( "SELECT 3" );
	}
	public function inside_closure(): void {
		$callback = static function() {
			global $wpdb;
			$wpdb->get_col( "SELECT 4" );
		};
		$callback();
	}
	public function non_sql_methods(): void {
		global $wpdb;
		$wpdb->flush();
	}
	public function local_parameter( mixed $wpdb ): void {
		$wpdb->query( "SELECT 5" );
	}
}
'
		);

		$config = $this->write_config();
		$result = $this->run_phpstan( $config );

		$bad = $this->messages_for( $result, 'src/frontend/class-bad-bare.php' );
		$this->assertSame( 4, count( $bad ), implode( "\n", $bad ) );
		foreach ( $bad as $message ) {
			$this->assertStringContainsString( 'restricted to the storage layer boundary', $message );
		}
	}

	public function test_the_storage_boundary_is_allowed_for_both_paths(): void {
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
	public function bare_run(): void {
		global $wpdb;
		$db   = $wpdb;
		$db->query( "SELECT 3" );
	}
}
'
		);

		$config = $this->write_config();
		$result = $this->run_phpstan( $config );

		$ok = $this->messages_for( $result, 'src/storage/class-ok.php' );
		$this->assertSame( [], $ok, implode( "\n", $ok ) );
	}

	/**
	 * Writes the fixture PHPStan configuration with both the extension and
	 * the statement-level rule registered, the way the consuming plugin does.
	 */
	private function write_config(): string {
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
			. "        arguments:\n"
			. "            allowedPathParts:\n"
			. "                - /src/storage/\n"
			. "        tags:\n"
			. "            - phpstan.restrictedMethodUsageExtension\n"
			. "    -\n"
			. "        class: SeoGraphCS\\PhpStan\\StorageBoundarySqlRule\n"
			. "        arguments:\n"
			. "            allowedPathParts:\n"
			. "                - /src/storage/\n"
			. "        tags:\n"
			. "            - phpstan.rules.rule\n"
			 );

		return $config;
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
