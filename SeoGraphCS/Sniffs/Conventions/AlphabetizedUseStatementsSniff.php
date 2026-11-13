<?php
/**
 * Copyright (c) 2026 ProgressPlanner.
 *
 * Licensed under the MIT license.
 * See the file LICENSE or https://github.com/ProgressPlanner/SeoGraphCS for details.
 */

declare(strict_types=1);

namespace SeoGraphCS\Sniffs\Conventions;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Requires first-party PHP `use` import blocks to be sorted alphabetically.
 *
 * The convention: within a file, every contiguous group of namespace
 * imports is ordered alphabetically by fully qualified name
 * (case-sensitive byte order, the same order PHP and this standard use
 * elsewhere), with one import per line and no blank line inside the group.
 * `use function` and `use const` imports are outside the convention and
 * are never reported or reordered; trait `use` statements inside class,
 * interface, or trait bodies are ignored entirely.
 *
 * The sniff reports one message per mis-ordered import block (pointing at
 * the first import that breaks the order). The diagnostic is report-only:
 * re-sorting a block is a one-time mechanical operation, and keeping the
 * sniff out of the in-place fixer keeps the convention from ever rewriting
 * import blocks during a normal PHPCBF run.
 */
final class AlphabetizedUseStatementsSniff implements Sniff {
	/**
	 * Message when a contiguous import block is not sorted.
	 *
	 * @var string
	 */
	public const UNSORTED_MESSAGE = 'Import %1$s must come before import %2$s; namespace imports must be sorted alphabetically';

	/**
	 * Files whose full check has already run (one report per file).
	 *
	 * @var array<string,bool>
	 */
	private $processed_files = [];

	/**
	 * Register the token types this sniff listens on.
	 *
	 * @return int[]
	 */
	public function register(): array {
		return [ \T_USE ];
	}

	/**
	 * Processes the file: runs the full import-block check once per file.
	 *
	 * @param File $phpcsFile The file being scanned.
	 * @param int  $stackPtr  The position of the current T_USE token.
	 *
	 * @return void
	 */
	public function process( File $phpcsFile, $stackPtr ): void {
		$file_name = $phpcsFile->getFilename();
		if ( isset( $this->processed_files[ $file_name ] ) ) {
			return;
		}
		$this->processed_files[ $file_name ] = true;

		$tokens = $phpcsFile->getTokens();

		// Closure variable captures are `use (...)`, never namespace imports.
		$next = $phpcsFile->findNext( [ \T_WHITESPACE, \T_COMMENT, \T_DOC_COMMENT ], $stackPtr + 1, null, true );
		if ( false !== $next && '(' === $tokens[ $next ]['content'] ) {
			return;
		}

		// Trait use statements live inside a class, interface, or trait body.
		if ( $this->is_inside_type_body( $tokens, $stackPtr ) ) {
			return;
		}

		foreach ( $this->collect_import_blocks( $phpcsFile, $tokens ) as $block ) {
			$this->check_block( $phpcsFile, $block );
		}
	}

	/**
	 * Checks one contiguous import block: report the first import that is not
	 * in its sorted position (the block's expected neighbor).
	 *
	 * @param File              $phpcsFile The file being scanned.
	 * @param array<int,array{name:string,line:string,start_ptr:int,end_ptr:int,name_ptr:int}> $block The block.
	 *
	 * @return void
	 */
	private function check_block( File $phpcsFile, array $block ): void {
		if ( count( $block ) < 2 ) {
			return;
		}

		$names = array_map(
			static function ( array $import ): string {
				return $import['name'];
			},
			$block
		);

		$sorted = $names;
		sort( $sorted, SORT_STRING );

		if ( $names === $sorted ) {
			return;
		}

		foreach ( $block as $i => $import ) {
			if ( $names[ $i ] !== $sorted[ $i ] ) {
				$expected = $sorted[ $this->sorted_index_of( $names, $names[ $i ] ) ];
				$phpcsFile->addError(
					sprintf( self::UNSORTED_MESSAGE, $expected, $names[ $i ] ),
					$import['name_ptr'],
					'Unsorted',
					[ $expected, $names[ $i ] ]
				);
				return;
			}
		}
	}

	/**
	 * Collects every contiguous top-level namespace-import block in the file
	 * (a blank line or any non-import statement starts a new block).
	 *
	 * @param File              $phpcsFile The file being scanned.
	 * @param array<int,array>  $tokens    The file tokens.
	 *
	 * @return array<int,array<int,array{name:string,line:string,start_ptr:int,end_ptr:int,name_ptr:int}>>
	 */
	private function collect_import_blocks( File $phpcsFile, array $tokens ): array {
		$all = [];
		foreach ( array_keys( $tokens ) as $i ) {
			if ( \T_USE !== $tokens[ $i ]['code'] ) {
				continue;
			}
			// `use function` / `use const` are outside the convention.
			$next = $phpcsFile->findNext( [ \T_WHITESPACE, \T_COMMENT, \T_DOC_COMMENT ], $i + 1, null, true );
			$keyword = false !== $next ? $tokens[ $next ]['content'] : '';
			if ( 'function' === $keyword || 'const' === $keyword ) {
				continue;
			}
			if ( $this->is_inside_type_body( $tokens, $i ) ) {
				continue;
			}
			$end_ptr = $this->statement_end( $phpcsFile, $tokens, $i );
			$raw     = '';
			for ( $j = $i; $j <= $end_ptr; $j++ ) {
				$raw .= $tokens[ $j ]['content'];
			}
			$all[] = [
				'use_ptr'  => $i,
				'end_ptr'  => $end_ptr,
				'raw'      => trim( $raw ),
				'name'     => $this->import_name( $raw ),
				'name_ptr' => false !== $next ? $next : ( $i + 1 ),
			];
		}

		if ( [] === $all ) {
			return [];
		}

		// Group the imports into contiguous blocks: a blank line or any
		// non-import statement between two imports starts a new block.
		$blocks = [];
		$block  = [];
		foreach ( $all as $import ) {
			if ( [] !== $block ) {
				$prev = $block[ \count( $block ) - 1 ];
				$between = $this->block_between( $phpcsFile, $tokens, $prev['end_ptr'], $import['use_ptr'] );
				if ( '' !== trim( $between ) ) {
					$blocks[] = $block;
					$block    = [];
				}
			}
			$block[] = [
				'name'      => $import['name'],
				'name_ptr'  => $import['name_ptr'],
				'start_ptr' => $import['use_ptr'],
				'end_ptr'   => $import['end_ptr'],
				'line'      => $import['raw'],
			];
		}

		if ( [] !== $block ) {
			$blocks[] = $block;
		}

		return $blocks;
	}

	/**
	 * Fully qualified name of the import (alias or group ignored).
	 *
	 * @param File       $phpcsFile The file being scanned.
	 * @param array<int,array> $tokens The file tokens.
	 * @param int        $use_ptr   Position of the T_USE token.
	 *
	 * @return string
	 */
	private function import_name( string $raw ): string {
		// Sort key from the raw statement: strip the `use` keyword and a
		// leading backslash, drop an `as Alias` suffix; for a group import
		// (`use A\B { C, D }`) the shared prefix is the key.
		if ( str_starts_with( $raw, 'use' ) ) {
			$raw = ltrim( substr( $raw, 3 ) );
		}
		if ( str_contains( $raw, '{' ) ) {
			$raw = substr( $raw, 0, strpos( $raw, '{' ) );
		}
		if ( str_contains( $raw, ' as ' ) ) {
			$raw = substr( $raw, 0, strpos( $raw, ' as ' ) );
		}

		return ltrim( trim( $raw ), '\\' );
	}

	/**
	 * Token pointer of the semicolon ending the statement starting at $use_ptr.
	 *
	 * @param File       $phpcsFile The file being scanned.
	 * @param array<int,array> $tokens The file tokens.
	 * @param int        $use_ptr   Position of the T_USE token.
	 *
	 * @return int
	 */
	private function statement_end( File $phpcsFile, array $tokens, int $use_ptr ): int {
		// Find the T_SEMICOLON that follows the use token, skipping over the
		// body of a group import (its inner semicolons end members, not the
		// statement): track brace depth.
		$depth = 0;
		for ( $i = $use_ptr; $i < \count( $tokens ); $i++ ) {
			$code = $tokens[ $i ]['code'];
			if ( \T_OPEN_CURLY_BRACKET === $code ) {
				$depth++;
			}
			if ( \T_CLOSE_CURLY_BRACKET === $code ) {
				if ( 0 === $depth ) {
					break; // left the statement (defensive)
				}
				$depth--;
			}
			if ( \T_SEMICOLON === $code && 0 === $depth ) {
				return $i;
			}
		}
		return $use_ptr;
	}

	/**
	 * Raw text between two token pointers (exclusive on both ends).
	 *
	 * @param File       $phpcsFile The file being scanned.
	 * @param array<int,array> $tokens The file tokens.
	 * @param int        $start     First excluded pointer.
	 * @param int        $end       Last excluded pointer.
	 *
	 * @return string
	 */
	private function block_between( File $phpcsFile, array $tokens, int $start, int $end ): string {
		$out = '';
		for ( $i = $start + 1; $i < $end; $i++ ) {
			$out .= $tokens[ $i ]['content'];
		}
		return $out;
	}

	/**
	 * Whether a token sits inside a function or type body (imports there are
	 * not namespace imports; closure captures are already excluded earlier).
	 *
	 * @param array<int,array> $tokens   The file tokens.
	 * @param int              $stackPtr The token to test.
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
			$code = $tokens[ $condition ]['code'];
			if ( in_array( $code, [ \T_CLASS, \T_INTERFACE, \T_TRAIT, \T_FUNCTION ], true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Position of a name in an ordered list (fallback to 0 when absent).
	 *
	 * @param string[] $list      The list.
	 * @param string   $needle    The name.
	 *
	 * @return int
	 */
	private function sorted_index_of( array $list, string $needle ): int {
		foreach ( $list as $i => $value ) {
			if ( $value === $needle ) {
				return $i;
			}
		}
		return 0;
	}
}
