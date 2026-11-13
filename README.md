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

Two companions enforce the consumer's direct-SQL boundary (requires PHPStan
>= 2.1):

- `SeoGraphCS\PhpStan\StorageBoundarySqlExtension` implements PHPStan's
  `RestrictedMethodUsageExtension`. The SQL method list (`query`, `get_var`,
  `get_row`, `get_results`, `get_col`, `prepare`, `insert`, `update`,
  `replace`, `delete`) is rejected on `wpdb` and its subclasses in any file
  outside the configured path fragments. It reuses PHPStan's resolved type
  information, so aliases of the real WordPress `wpdb` global — including
  aliases held in arrays — are rejected wherever the stubs or a
  `/** @var \wpdb $wpdb */` annotation make the global resolvable, while
  unrelated objects with similarly named methods stay valid. In analysis runs
  that load no WordPress stubs the extension stays inert, which keeps
  WordPress-independent packages covered without gaining a WordPress
  dependency.
- `SeoGraphCS\PhpStan\StorageBoundarySqlRule` covers the dominant bare
  `global $wpdb;` pattern even when the run resolves the global to `mixed`:
  for every analyzed file it pre-scans each function scope (memoized per
  file) for the `wpdb` global, single-level aliases assigned from it, and
  arrays that hold it, then reports SQL method calls on those variables
  outside the boundary — including calls inside nested closures. Call sites
  whose callee type already resolves to `wpdb` are left to the extension so
  the two never report the same line twice.

Register both in the consuming project's PHPStan configuration. PHPStan's
core `RestrictedMethodUsageRule` that executes the extension is
auto-registered; declaring it a second time in a consumer config makes every
extension report twice, so the snippet deliberately omits it:

```neon
services:
    -
        class: SeoGraphCS\PhpStan\StorageBoundarySqlExtension
        arguments:
            allowedPathParts:
                - /src/storage/
        tags:
            - phpstan.restrictedMethodUsageExtension
    -
        class: SeoGraphCS\PhpStan\StorageBoundarySqlRule
        arguments:
            allowedPathParts:
                - /src/storage/
        tags:
            - phpstan.rules.rule
```

The `allowedPathParts` fragments are matched against the normalized analyzed
file path; every listed fragment marks a privileged SQL boundary (the
repository default is the plugin's `src/storage/` layer).

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
