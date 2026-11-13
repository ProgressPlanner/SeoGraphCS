<?php
declare(strict_types=1);

namespace SeoGraphCS\PhpStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\FunctionLike;
use PhpParser\Node\Stmt\Global_;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * Statement-level companion to {@see StorageBoundarySqlExtension}.
 *
 * The type-driven extension only fires where the WordPress `wpdb` type is
 * resolvable (stubs plus `@var` annotations). This rule covers the dominant
 * bare `global $wpdb;` pattern even when the analysis run resolves the global
 * to `mixed`: for every analyzed file it pre-scans each function scope for
 * the `wpdb` global, single-level aliases assigned from it (including arrays
 * that hold it), and reports SQL method calls on those variables outside the
 * boundary. Call sites whose callee type already resolves to `wpdb` are left
 * to the extension to avoid double reporting.
 *
 * Requires PHPStan >= 2.1 (the Error identifier argument). The core
 * `RestrictedMethodUsageRule` that executes the extension is auto-registered
 * by PHPStan and must not be declared a second time in the consuming config.
 *
 * Register in the consuming project's PHPStan configuration:
 *
 * ```neon
 * services:
 *     -
 *         class: SeoGraphCS\PhpStan\StorageBoundarySqlExtension
 *         arguments:
 *             allowedPathParts:
 *                 - /src/storage/
 *         tags:
 *             - phpstan.restrictedMethodUsageExtension
 *     -
 *         class: SeoGraphCS\PhpStan\StorageBoundarySqlRule
 *         arguments:
 *             allowedPathParts:
 *                 - /src/storage/
 *         tags:
 *             - phpstan.rules.rule
 * ```
 */
final class StorageBoundarySqlRule implements Rule {

	/**
	 * Per-file function-scope table: file => list of
	 * [ int startLine, int endLine, array<string, true> tracked ].
	 *
	 * @var array<string, array<int, array{int, int, array<string, true>}>>
	 */
	private array $scopeCache = [];

	/**
	 * @var ReflectionProvider
	 */
	private ReflectionProvider $reflectionProvider;

	/**
	 * Normalized path fragments that mark the privileged SQL boundary.
	 *
	 * @var list<string>
	 */
	private array $allowedPathParts;

	/**
	 * @param ReflectionProvider $reflectionProvider Provider used to test for wpdb subclasses.
	 * @param list<string>       $allowedPathParts   Path fragments whose files may use direct SQL.
	 */
	public function __construct( ReflectionProvider $reflectionProvider, array $allowedPathParts = [ '/src/storage/' ] ) {
		$this->reflectionProvider = $reflectionProvider;
		$this->allowedPathParts   = $allowedPathParts;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getNodeType(): string {
		return Node\Expr\MethodCall::class;
	}

	/**
	 * {@inheritdoc}
	 *
	 * @return \PHPStan\Rules\RuleError[]
	 */
	public function processNode( Node $node, Scope $scope ): array {
		// Plain method names surface as a string or an Identifier depending on
		// the parser version; dynamic names never match the fixed SQL list.
		$methodName = null;
		if ( is_string( $node->name ) ) {
			$methodName = strtolower( $node->name );
		} elseif ( $node->name instanceof Node\Identifier ) {
			$methodName = strtolower( (string) $node->name->name );
		}

		if ( $methodName === null || ! isset( StorageBoundarySqlExtension::SQL_METHODS[ $methodName ] ) ) {
			return [];
		}

		if ( ! $this->isOutsideBoundary( $scope->getFile() ) ) {
			return [];
		}

		if ( $node->var instanceof Variable && is_string( $node->var->name ) ) {
			$variable = $node->var->name;
		} elseif ( $node->var instanceof ArrayDimFetch && $node->var->var instanceof Variable && is_string( $node->var->var->name ) ) {
			$variable = $node->var->var->name;
		} else {
			return [];
		}

		// The type-driven extension owns every call site where PHPStan already
		// resolves the callee to wpdb (stubs plus @var annotations); this rule
		// exists for the unresolvable bare-global pattern.
		if ( $this->typeCoversWpdb( $scope->getType( $node->var ) ) ) {
			return [];
		}

		$tracked = $this->trackedVariablesAt( $scope->getFile(), $node->getLine() );

		if ( ! isset( $tracked[ $variable ] ) ) {
			return [];
		}

		return [
			RuleErrorBuilder::message(
				'Direct SQL through the wpdb global (or an alias of it) is restricted to the storage layer boundary.'
			)
				->identifier( 'seograph.directSqlOutsideStorage' )
				->build(),
		];
	}

	/**
	 * Whether the file lies outside the configured SQL boundary.
	 */
	private function isOutsideBoundary( string $file ): bool {
		$file = str_replace( '\\', '/', $file );
		foreach ( $this->allowedPathParts as $part ) {
			if ( str_contains( $file, $part ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether a resolved type is wpdb or a subclass of wpdb.
	 */
	private function typeCoversWpdb( \PHPStan\Type\Type $type ): bool {
		foreach ( $type->getObjectClassNames() as $className ) {
			if ( strtolower( $className ) === 'wpdb' ) {
				return true;
			}
			if ( $this->reflectionProvider->hasClass( $className )
				&& $this->reflectionProvider->getClass( $className )->isSubclassOf( 'wpdb' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The tracked variables of the innermost function scope containing the line.
	 *
	 * @return array<string, true>
	 */
	private function trackedVariablesAt( string $file, int $line ): array {
		$best      = [];
		$bestWidth = null;

		foreach ( $this->scopeTable( $file ) as $entry ) {
			if ( $entry[0] <= $line && $line <= $entry[1] ) {
				$width = $entry[1] - $entry[0];
				if ( $bestWidth === null || $width < $bestWidth ) {
					$best      = $entry[2];
					$bestWidth = $width;
				}
			}
		}

		return $best;
	}

	/**
	 * Builds (and memoizes) the function-scope table for one file: every
	 * function-like statement with its line span and its tracked variable set.
	 *
	 * @return array<int, array{int, int, array<string, true>}>
	 */
	private function scopeTable( string $file ): array {
		if ( isset( $this->scopeCache[ $file ] ) ) {
			return $this->scopeCache[ $file ];
		}

		$table = [];
		$code  = @file_get_contents( $file );
		if ( $code !== false ) {
			try {
				$parser    = ( new \PhpParser\ParserFactory() )->createForHostVersion();
				$ast       = $parser->parse( $code );
				$collector = new class() extends NodeVisitorAbstract {
					/** @var array<int, array{int, int, array<string, true>}> */
					public $scopes = [];

					public function enterNode( Node $node ) {
						if ( $node instanceof FunctionLike ) {
							$this->scopes[] = [
								$node->getStartLine(),
								$node->getEndLine(),
								StorageBoundarySqlRule::trackedVariables( $node ),
							];
						}

						return null;
					}
				};
				if ( is_array( $ast ) ) {
					$traverser = new NodeTraverser();
					$traverser->addVisitor( $collector );
					$traverser->traverse( $ast );
					$table = $collector->scopes;
				}
			} catch ( \Throwable $e ) {
				// A file PHPStan already parsed should always parse here; if it
				// does not, the rule degrades to the extension-only behavior.
			}
		}

		$this->scopeCache[ $file ] = $table;

		return $table;
	}

	/**
	 * The tracked variables of one function scope: `global $wpdb`, single-level
	 * aliases assigned from it, and arrays that hold it. Nested functions are
	 * separate scopes and are excluded from the walk.
	 *
	 * @param FunctionLike $functionLike The function, method, closure or arrow function.
	 *
	 * @return array<string, true>
	 */
	public static function trackedVariables( FunctionLike $functionLike ): array {
		$stmts      = $functionLike->getStmts();
		$statements = is_array( $stmts ) ? array_values( $stmts ) : [ $stmts ];

		$tracked = [];
		foreach ( $statements as $statement ) {
			self::walk( $statement, $tracked );
		}

		return $tracked;
	}

	/**
	 * Recursively visits every node under the statement (the statement itself
	 * included), tracking `global $wpdb` and assignments from tracked
	 * variables. Nodes inside nested functions are excluded.
	 *
	 * @param Node               $node    The node to start from.
	 * @param array<string,true> $tracked Tracked names, filled in place.
	 */
	private static function walk( Node $node, array &$tracked ): void {
		if ( $node instanceof Function_
			|| $node instanceof Closure
			|| $node instanceof ArrowFunction ) {
			return;
		}

		if ( $node instanceof Global_ ) {
			foreach ( $node->vars as $var ) {
				if ( $var instanceof Variable && is_string( $var->name ) && 'wpdb' === $var->name ) {
					$tracked['wpdb'] = true;
				}
			}
		}

		if ( $node instanceof Node\Expr\Assign ) {
			$source = self::assignmentSource( $node->expr, $tracked );
			if ( $source !== null ) {
				if ( $node->var instanceof Variable && is_string( $node->var->name ) ) {
					$tracked[ $node->var->name ] = true;
				} elseif ( $node->var instanceof ArrayDimFetch && $node->var->var instanceof Variable && is_string( $node->var->var->name ) ) {
					$tracked[ $node->var->var->name ] = true;
				}
			}
		}

		foreach ( self::childNodes( $node ) as $child ) {
			self::walk( $child, $tracked );
		}
	}

	/**
	 * Yields the node's child nodes, portably across php-parser 4 and 5
	 * (the newer getSubNodeObjects() is absent in the vendored 4.x series).
	 *
	 * @param Node $node The node.
	 *
	 * @return iterable<Node>
	 */
	private static function childNodes( Node $node ): iterable {
		foreach ( $node->getSubNodeNames() as $name ) {
			$value = $node->{$name};
			if ( $value instanceof Node ) {
				yield $value;
			} elseif ( is_array( $value ) ) {
				foreach ( $value as $item ) {
					if ( $item instanceof Node ) {
						yield $item;
					}
				}
			}
		}
	}

	/**
	 * Returns a tracked variable name when the assignment expression derives
	 * from a tracked value, `null` otherwise.
	 *
	 * @param array<string, true> $tracked Tracked names, read only.
	 */
	private static function assignmentSource( Node\Expr $expr, array $tracked ): ?string {
		if ( $expr instanceof Variable && is_string( $expr->name ) ) {
			return isset( $tracked[ $expr->name ] ) ? $expr->name : null;
		}

		if ( $expr instanceof Array_ ) {
			foreach ( $expr->items as $item ) {
				if ( $item !== null && $item->value instanceof Variable && is_string( $item->value->name ) && isset( $tracked[ $item->value->name ] ) ) {
					return $item->value->name;
				}
			}
		}

		return null;
	}
}

