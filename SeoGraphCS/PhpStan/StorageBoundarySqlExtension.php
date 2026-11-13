<?php
declare(strict_types=1);

namespace SeoGraphCS\PhpStan;

use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ExtendedMethodReflection;
use PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageExtension;
use PHPStan\Rules\RestrictedUsage\RestrictedUsage;

/**
 * Restricts direct SQL method calls to the project's storage boundary.
 *
 * The check keys on the resolved declaring class, so ordinary aliases of the
 * real WordPress `wpdb` global — including aliases held in arrays — are
 * rejected outside the boundary, while unrelated objects that happen to
 * expose a similarly named method stay valid. In analysis runs that load no
 * WordPress stubs (the portable graph core), `wpdb` is simply unknown and
 * the extension stays inert.
 *
 * Requires PHPStan >= 2.1 (ExtendedMethodReflection, Scope::getFile, the
 * restrictedMethodUsageExtension service tag).
 *
 * Register in the consuming project's PHPStan configuration:
 *
 * ```neon
 * services:
 *     -
 *         class: SeoGraphCS\PhpStan\StorageBoundarySqlExtension
 *         tags:
 *             - phpstan.restrictedMethodUsageExtension
 *         arguments:
 *             allowedPathParts:
 *                 - /src/storage/
 * ```
 */
final class StorageBoundarySqlExtension implements RestrictedMethodUsageExtension {

	/**
	 * Wpdb methods that represent direct SQL access.
	 *
	 * @var array<string, true>
	 */
	private const SQL_METHODS = [
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
	 * Normalized path fragments that mark the privileged SQL boundary.
	 *
	 * @var list<string>
	 */
	private array $allowedPathParts;

	/**
	 * @param list<string> $allowedPathParts Path fragments whose files may use direct SQL.
	 */
	public function __construct(array $allowedPathParts = [ '/src/storage/' ]) {
		$this->allowedPathParts = $allowedPathParts;
	}

	/**
	 * {@inheritdoc}
	 */
	public function isRestrictedMethodUsage( ExtendedMethodReflection $methodReflection, Scope $scope ): ?RestrictedUsage {
		$declaringClass = $methodReflection->getDeclaringClass();
		$className      = strtolower( $declaringClass->getName() );

		if ( 'wpdb' !== $className && ! $declaringClass->isSubclassOf( 'wpdb' ) ) {
			return null;
		}

		if ( ! isset( self::SQL_METHODS[ strtolower( $methodReflection->getName() ) ] ) ) {
			return null;
		}

		$file = str_replace( '\\', '/', $scope->getFile() );
		foreach ( $this->allowedPathParts as $part ) {
			if ( str_contains( $file, $part ) ) {
				return null;
			}
		}

		return RestrictedUsage::create(
			'Direct SQL through wpdb (or a wpdb subclass) is restricted to the storage layer boundary.',
			'seograph.directSqlOutsideStorage'
		);
	}
}
