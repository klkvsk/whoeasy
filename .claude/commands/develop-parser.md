# Develop WHOIS Parser

Iteratively fix the WHOIS parser so that all fixture tests pass — parsed output must match `.expected.json` for every fixture.

## Loop

1. **Run tests**: `./dev php vendor/bin/phpunit tests/Unit/WhoisFixtureTest.php` (use `--testdox` for readable output)
2. **Analyze failures**: For each failing test, compare expected vs actual output. Group failures by root cause (e.g. "missing field X for all .za servers", "date not parsed for format D-M-Y").
3. **Run PHPStan**: `vendor/bin/phpstan analyse` — all code must pass at level max.
4. **Fix**: Apply the smallest change that fixes the most tests. Prefer changes in this order:
   a. Fix field name normalization in `normalizeKey()` — add missing aliases
   b. Fix extraction logic in `parseDomain()` / `parseIp()` / `parseAsn()` — handle missing fields
   c. Fix date parsing in `parseDate()` — add missing date formats
   d. Fix contact/registrar/nameserver extraction — handle edge cases
   e. Add server-specific parsing only as a last resort — when a server uses a fundamentally different format (like Nominet indented sections)
5. **Re-run tests and PHPStan** to verify fixes and check for regressions.
6. **Repeat** until all fixture tests and PHPStan pass (or only known-broken fixtures remain).

## Architecture context

The parser lives in `src/Parser/Whois/WhoisParser.php`. Key methods:

- `parse()` — entry point: strips boilerplate → extracts fields → routes to type parser
- `extractFields()` — parses `Key: Value` lines, normalizes keys via `normalizeKey()`
- `normalizeKey()` — maps field name variations to canonical keys (e.g. `domain_name`, `creation_date`)
- `parseDomain()` — builds `DomainInfo` from normalized fields
- `parseIp()` — builds `IpInfo` from normalized fields
- `parseAsn()` — builds `AsnInfo` from normalized fields
- `extractContacts()` — extracts contacts from `{type}_{field}` patterns
- `parseDate()` — normalizes dates to `Y-m-d H:i:s` with format fallback chain
- `filterRedacted()` — nullifies GDPR/privacy placeholders

Field extraction flow:
```
Raw text → stripBoilerplate() → extractFields() → normalizeKey() per line
                                                    ↓
                                            fields["domain_name"] = ["example.com"]
                                            fields["creation_date"] = ["2020-01-01"]
                                            fields["name_server"] = ["ns1.ex.com", "ns2.ex.com"]
                                                    ↓
                                            parseDomain() / parseIp() / parseAsn()
                                                    ↓
                                            DomainInfo / IpInfo / AsnInfo
                                                    ↓
                                            toArray() → compared against expected JSON
```

Special formats already handled:
- UK Nominet indented sections (`parseIndentedSections()`)
- EPP status URL stripping
- RDAP/privacy redaction filtering

## Rules

- **Never modify `.expected.json` files** — those are ground truth. Fix the parser instead.
- **Never modify test files** — only modify parser source code in `src/`.
- **All changes must pass PHPStan at level max** — no new type errors. Use proper type guards (`is_string()`, `is_array()`) instead of casts on `mixed`.
- Keep changes minimal and focused. Don't refactor unrelated code.
- When adding a field alias to `normalizeKey()`, check if other servers use the same alias to avoid regressions.
- When adding date formats to `parseDate()`, add them in specificity order (most specific first) to avoid ambiguous parsing.
- For server-specific logic, prefer detecting the format from the response content (not the server hostname) when possible.
- Run the full fixture test suite after each change, not just the specific failing test.

## Debugging tips

- To see what the parser actually extracts, add a temporary `var_dump($fields)` after `extractFields()` and run a single test: `php vendor/bin/phpunit --filter="server/domain"`
- To run a single fixture: `./dev php vendor/bin/phpunit --filter="whois.tld.ee/tr.ee"`
- Skipped tests (`S`) mean empty `{}` expected files — ignore those.
- The test comparison uses `assertSame` (strict equality) — field order, types, and values must match exactly.

## Reporting

After each iteration, briefly report:
- How many tests pass / fail / skip
- What you fixed
- What failures remain (grouped by cause)
