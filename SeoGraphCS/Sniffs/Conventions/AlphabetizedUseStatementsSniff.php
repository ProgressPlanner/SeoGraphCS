<?php
/**
 * Enforces the SEO Graph alphabetized-import convention.
 *
 * @package SeoGraphCS
 */

namespace SeoGraphCS\Sniffs\Conventions;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Requires a file's namespace import statements to be ordered alphabetically.
 *
 * The ordering compares the fully qualified name each import introduces
 * (a grouped import orders by its first expanded member) using byte-wise
 * string comparison. Trait `use` statements inside classes are not imports
 * and are ignored; `use function` and `use const` statements are outside the
 * convention and are ignored as well.
 */
class AlphabetizedUseStatementsSniff implements Sniff {

	/**
	 * Files already processed by this sniff.
	 *
	 * @var array<string, true>
	 */
	private array $processed = [];

	/**
	 * Implements this sniff.
	 *
	 * @param File $phpcsFile The file being scanned.
	 *
	 * @return void|int Last stack pointer processed.
	 */
	public function register(): array {
		return [ \T_USE ];
	}

	/**
	 * Implements this sniff.
	 *
	 * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
	 * @param int                         $stackPtr  The position of the current token.
	 *
	 * @return void
	 */
	public function process( File $phpcsFile, $stackPtr ): void {
		// The sniff is invoked once per use statement; run the full check only
		// once per file so reports are not duplicated.
		$file_name = $phpcsFile->getFilename();
		if ( isset( $this->processed[ $file_name ] ) ) {
			return;
		}
		$this->processed[ $file_name ] = true;

		$tokens = $phpcsFile->getTokens();

		// Closure variable captures are `use (...)`, never `use \Name\Path`.
		$next = $phpcsFile->findNext( [ \T_WHITESPACE, \T_COMMENT, \T_DOC_COMMENT ], $stackPtr + 1, null, true );
		if ( false !== $next && '(' === $tokens[ $next ]['content'] ) {
			return;
		}

		// Trait use statements live inside a class, interface, or trait body;
		// only namespace-level imports are subject to the convention.
		if ( $this->is_inside_type_body( $tokens, $stackPtr ) ) {
			return;
		}

		// `use function` / `use const` statements are outside the convention.
		$next = $phpcsFile->findNext( [ \T_WHITESPACE, \T_COMMENT, \T_DOC_COMMENT ], $stackPtr + 1, null, true );
		if ( false !== $next ) {
			$keyword = $tokens[ $next ]['content'];
			if ( 'function' === $keyword || 'const' === $keyword ) {
				return;
			}
		}

		$imports = $this->collect_imports( $phpcsFile, $tokens );
		if ( count( $imports ) < 2 ) {
			return;
		}

		$highest_seen = '';
		foreach ( $imports as $import ) {
			if ( '' !== $highest_seen && strcmp( $highest_seen, $import['first_name'] ) > 0 ) {
				$message = sprintf(
					'Import "%s" must come before import "%s"; namespace imports must be sorted alphabetically by fully qualified name.',
					$import['first_name'],
					$highest_seen
				);
				$phpcsFile->addFixableError( $message, $import['ptr'], 'Unsorted' );
				$this->apply_block_fix( $phpcsFile, $imports );
				return;
			}

			$highest_seen = $import['first_name'];
		}
	}

	/**
	 * Collects the namespace-level imports of a file, in file order.
	 *
	 * @param File $phpcsFile The file being scanned.
	 *
	 * @return array<int,array<string,mixed>> Import descriptors.
	 */
	private function collect_imports( File $phpcsFile ): array {
		$tokens  = $phpcsFile->getTokens();
		$imports = [];
		foreach ( $tokens as $ptr => $token ) {
			if ( \T_USE !== $token['code'] ) {
				continue;
			}

			if ( $this->is_inside_type_body( $tokens, $ptr ) ) {
				continue;
			}

			$next = $phpcsFile->findNext( [ \T_WHITESPACE, \T_COMMENT, \T_DOC_COMMENT ], $ptr + 1, null, true );
			if ( false !== $next && ( 'function' === $tokens[ $next ]['content'] || 'const' === $tokens[ $next ]['content'] ) ) {
				continue;
			}

			$raw = '';
			$end = $ptr;
			for ( $i = $ptr; $i < count( $tokens ); $i++ ) {
				$raw .= $tokens[ $i ]['content'];
				$end = $i;
				if ( ';' === $tokens[ $i ]['content'] || '}' === $tokens[ $i ]['content'] ) {
					break;
				}
			}
			if ( '' === trim( $raw ) ) {
				continue;
			}

			$statement = ltrim( substr( $raw, 3 ) );
			if ( '' !== $statement && ( str_starts_with( $statement, 'function' ) || str_starts_with( $statement, 'const' ) ) ) {
				continue;
			}

			$import = $this->parse_import( $statement );
			if ( null === $import ) {
				continue;
			}

			$import['ptr']        = $ptr;
			$import['end_ptr']    = $end;
			$import['raw']        = trim( $raw );
			$imports[ count( $imports ) ] = $import;
		}

		return array_values( $imports );
	}

	/**
	 * Parses one import statement into a comparable descriptor.
	 *
	 * @param string $statement The statement text after the `use` keyword.
	 *
	 * @return array<string,mixed>|null The descriptor, or null when unparseable.
	 */
	private function parse_import( string $statement ): ?array {
		$statement = trim( $statement );
		if ( '' === $statement ) {
			return null;
		}

		// Grouped import: prefix\{member, member, ...}
		if ( false !== strpos( $statement, '{' ) ) {
			$prefix   = ltrim( substr( $statement, 0, strpos( $statement, '{' ) ), '\\' );
			$inner    = trim( substr( $statement, strpos( $statement, '{' ) + 1, strrpos( $statement, '}' ) - strpos( $statement, '{' ) - 1 ) );
			$members  = array_map(
				static function ( string $member ): string {
					return ltrim( trim( $member ), '\\' );
				},
				explode( ',', $inner )
			);
			$members  = array_values( array_filter( $members, static fn ( string $member ): bool => '' !== $member ) );
			if ( '' === $prefix || [] === $members ) {
				return null;
			}

			$expanded = array_map(
				static function ( string $member ) use ( $prefix ): string {
					return $prefix . '\\' . $member;
				},
				$members
			);

			return [
				'first_name' => $expanded[0],
				'names'      => $expanded,
				'grouped'    => true,
			];
		}

		$name = ltrim( rtrim( $statement, ';' ), chr(92) );
		if ( '' === $name ) {
			return null;
		}

		return [
			'first_name' => $name,
			'names'      => [ $name ],
			'grouped'    => false,
		];
	}

	/**
	 * Reorders a contiguous import block into alphabetical order.
	 *
	 * The fix only applies when the block is contiguous (no non-whitespace
	 * content between the statements); anything else is reported but left
	 * for the author to sort manually.
	 *
	 * @param File                           $phpcsFile The file being scanned.
	 * @param array<int,array<string,mixed>> $tokens    The file tokens.
	 * @param array<int,array<string,mixed>> $imports   Import descriptors in file order.
	 *
	 * @return void
	 */
	private function apply_block_fix( File $phpcsFile, array $imports ): void {
		$first  = $imports[0];
		$last   = $imports[ count( $imports ) - 1 ];
		$tokens = $phpcsFile->getTokens();

		// Contiguity guard: every token between the first use and the last
		// terminator must belong to one of the statements or be whitespace.
		$covered = [];
		foreach ( $imports as $import ) {
			for ( $i = $import['ptr']; $i <= $import['end_ptr']; $i++ ) {
				$covered[ $i ] = true;
			}
		}
		for ( $i = $first['ptr']; $i <= $last['end_ptr']; $i++ ) {
			if ( isset( $covered[ $i ] ) ) {
				continue;
			}
			if ( \T_WHITESPACE !== $tokens[ $i ]['code'] && ! in_array( $tokens[ $i ]['code'], [ \T_COMMENT, \T_DOC_COMMENT ], true ) ) {
				return;
			}
		}

		$ordered = $imports;
		usort(
			$ordered,
			static function ( array $a, array $b ): int {
				return strcmp( $a['first_name'], $b['first_name'] );
			}
		);

		$fix = $phpcsFile->fixer;
		if ( null === $fix ) {
			return;
		}

		$original_block = '';
		for ( $i = $first['ptr']; $i <= $last['end_ptr']; $i++ ) {
			$original_block .= $tokens[ $i ]['content'];
		}
		$original_lines = explode( "\n", $original_block );
		$indent         = ltrim( array_shift( $original_lines ), "\t " );

		$fixed_lines = [];
		foreach ( $ordered as $index => $import ) {
			$line = $import['raw'];
			if ( $index > 0 ) {
				$line = $indent . $line;
			}
			$fixed_lines[] = $line;
		}

		$fix->beginChangeset();
		$fix->replaceToken( $first['ptr'], implode( "\n", $fixed_lines ) );
		for ( $i = $first['ptr'] + 1; $i <= $last['end_ptr']; $i++ ) {
			$fix->replaceToken( $i, '' );
		}
		$fix->endChangeset();
	}
	/**
	 * Whether a token sits inside a class, interface, or trait body.
	 *
	 * @param array<int,array<string,mixed>> $tokens   The file tokens.
	 * @param int                            $stackPtr The token to test.
	 *
	 * @return bool
	 */
	private function is_inside_type_body( array $tokens, int $stackPtr ): bool {
		foreach ( $tokens[ $stackPtr ]['conditions'] ?? [] as $condition ) {
			// Some PHPCS builds store non-pointer values in the condition
			// stack; only integer token pointers can be dereferenced.
			if ( ! is_int( $condition ) || ! isset( $tokens[ $condition ] ) ) {
				continue;
			}
			if ( in_array( $tokens[ $condition ]['code'], [ \T_CLASS, \T_INTERFACE, \T_TRAIT, \T_FUNCTION ], true ) ) {
				return true;
			}
		}

		return false;
	}
}

