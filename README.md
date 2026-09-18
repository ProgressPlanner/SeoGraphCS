# SeoGraphCS

SeoGraphCS is the reusable PHP_CodeSniffer standard for SEO Graph projects. It
combines WordPress Coding Standards and PHPCompatibilityWP with hard
architecture checks for SEO Graph's runtime boundaries.

## Installation

```bash
composer require --dev progressplanner/seographcs:1.0.0
```

Reference the installed standard from the consuming repository's ruleset:

```xml
<rule ref="SeoGraphCS"/>
```

The consuming ruleset remains responsible for selecting files and declaring
repository-specific exclusions. SeoGraphCS owns the shared coding standard,
WordPress and PHP compatibility policy, naming and internationalization policy,
and the architecture-boundary sniff.

## Development

```bash
composer install
composer check
```
