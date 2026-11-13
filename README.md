# SeoGraphCS

SeoGraphCS is the reusable PHP_CodeSniffer standard for SEO Graph projects. It
combines WordPress Coding Standards and PHPCompatibilityWP with hard
architecture checks for SEO Graph's runtime boundaries and explicit project
conventions.

## Installation

```bash
composer require --dev progressplanner/seographcs:1.1.0
```

Reference the installed standard from the consuming repository's ruleset:

```xml
<rule ref="SeoGraphCS"/>
```

The consuming ruleset remains responsible for selecting files and declaring
repository-specific exclusions. SeoGraphCS owns the shared coding standard,
WordPress and PHP compatibility policy, naming and internationalization policy,
the architecture-boundary sniff, and the project convention sniffs.

## Conventions

- `SeoGraphCS.Conventions.AlphabetizedUseStatements` requires a file's
  namespace import statements to be sorted alphabetically by the fully
  qualified name each import introduces (a grouped import orders by its
  shared prefix, so it sorts before longer imports of that same prefix). The
  diagnostic is report-only: re-sorting an import block is a one-time
  mechanical edit, and the sniff deliberately never rewrites blocks in place
  during a `phpcbf` run. Trait `use` statements, `use function`, and
  `use const` statements are outside the convention and are ignored.

## Development

```bash
composer install
composer check
```
