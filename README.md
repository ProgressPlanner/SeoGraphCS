# SeoGraphCS

SeoGraphCS is the reusable PHP_CodeSniffer standard for SEO Graph projects. It
combines WordPress Coding Standards and PHPCompatibilityWP with hard
architecture checks for SEO Graph's runtime boundaries and explicit project
conventions.

## Installation

```bash
composer require --dev progressplanner/seographcs:1.2.0
```

Reference the installed standard from the consuming repository's ruleset:

```xml
<rule ref="SeoGraphCS"/>
```

The consuming ruleset remains responsible for selecting files and declaring
repository-specific exclusions. SeoGraphCS owns the shared coding standard,
WordPress and PHP compatibility policy, naming and internationalization policy,
the architecture-boundary sniff, and the project convention sniffs.

## PHPStan extensions

`SeoGraphCS\PhpStan\StorageBoundarySqlExtension` implements PHPStan's
`RestrictedMethodUsageExtension` (requires PHPStan >= 2.1) and restricts direct
SQL to the consumer's storage boundary: the SQL method list (`query`,
`get_var`, `get_row`, `get_results`, `get_col`, `prepare`, `insert`,
`update`, `replace`, `delete`) is rejected on `wpdb` and its subclasses in any
file outside the configured path fragments. It reuses PHPStan's resolved
type information, so ordinary aliases of the real WordPress `wpdb` global —
including aliases held in arrays — are rejected wherever the stubs or a
`/** @var \wpdb $wpdb */` annotation make the global resolvable, while
unrelated objects with similarly named methods stay valid. In analysis runs
that load no WordPress stubs the extension stays inert, which keeps
WordPress-independent packages covered without gaining a WordPress dependency.

Register it in the consuming project's PHPStan configuration:

```neon
services:
    -
        class: SeoGraphCS\PhpStan\StorageBoundarySqlExtension
        tags:
            - phpstan.restrictedMethodUsageExtension
        arguments:
            allowedPathParts:
                - /src/storage/
    -
        class: PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageRule
        tags:
            - phpstan.rules
```

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

The architecture sniff's head-output check inspects expression-local template
structure: locally known literal fragments plus opaque slots for runtime
values, matched against the protected tag families (document titles,
`meta` tags with `name`/`property`, `link` tags with `rel`, JSON-LD
`script` tags). Attribute order, whitespace, case and quoting cannot hide a
template; prebuilt tags whose values are concatenated from runtime data, and
complete raw tags used as comparison or search data, are rejected at their
source outside presenters. MIME data, escaped markup examples, structural
selectors and the standalone sitemap/XSL full-document rendering allowance
stay legal.
