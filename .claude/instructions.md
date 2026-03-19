# Whoeasy (klkvsk/whoeasy)

Unified WHOIS + RDAP query library for PHP 8.2+. Namespace: `Klkvsk\Whoeasy\`, PSR-4 mapped to `src/`.

## Architecture

### Core Flow

```
Whoeasy::query($input, ?QueryOptions)
  -> ServerRegistry::resolve($input)       // detect query type, find WHOIS/RDAP servers
  -> executeWhois() / executeRdap()        // fetch raw responses, follow referrals
     -> WhoisClient::query()               // TCP:43 single request
     -> WhoisParser::parse()               // raw text -> AbstractInfo
     -> RdapClient::query()                // HTTP/HTTPS single request
     -> RdapParser::parse()                // JSON -> AbstractInfo
  -> ResultMerger::merge()                 // combine if Both/Prefer mode with fallback
  -> QueryResult                           // info + protocol hops with errors
```

### Key Components

- **Whoeasy** (`src/Whoeasy.php`) — Entry point. Orchestrates query flow with 5 modes. Manages referral chains and hop merging. Never throws on empty results — returns QueryResult with error details in hops.
- **ServerRegistry** (`src/Registry/`) — O(log n) lookup of WHOIS/RDAP servers from pre-generated PHP arrays. Covers TLDs, IPv4/IPv6 ranges, ASN ranges.
- **WhoisClient** (`src/Client/Whois/WhoisClient.php`) — TCP:43 client via curl telnet. Single request, no referral logic (handled by Whoeasy).
- **HttpWhoisClient** (`src/Client/Whois/HttpWhoisClient.php`) — HTTP-based WHOIS for servers without port 43 (e.g. .ae, .gov.za).
- **RdapClient** (`src/Client/Rdap/RdapClient.php`) — HTTP/HTTPS client (ext-curl) for RFC 7480/9083.
- **WhoisParser** (`src/Parser/Whois/WhoisParser.php`) — Universal key:value parser. Handles all known TLDs via field name normalization. RPSL object parsing for IP/ASN (RIPE/APNIC/LACNIC/AFRINIC). ARIN-specific contact extraction. Static utility methods for boilerplate stripping, rate-limit/not-found detection, referral extraction.
- **RdapParser** (`src/Parser/Rdap/RdapParser.php`) — RFC 9083 JSON parser for domain/IP/ASN. Extracts registrar with ianaId and nested abuse contacts. Static methods for rate-limit/not-found detection, referral URL extraction, origin ASN extraction.
- **ResultMerger** (`src/Result/ResultMerger.php`) — Merges WHOIS + RDAP results. RDAP priority for scalars, combined+deduplicated for arrays. Same-type contacts preserved when distinct, merged when one is a subset of another.
- **QueryResult** (`src/Result/QueryResult.php`) — Final output with `info` (nullable AbstractInfo), `whois` and `rdap` ProtocolResults containing hops. Helper methods: `isNotFound()`, `hasRetryableErrors()`, `toArray()`.
- **ProtocolResult** (`src/Result/ProtocolResult.php`) — Holds merged info + array of hops for one protocol.
- **Result model** (`src/Result/Info/`) — readonly value objects: `DomainInfo`, `IpInfo`, `AsnInfo` (all extend `AbstractInfo`). Fields: `Contact`, `Registrar`, `Nameserver`, `ContactType` enum.
- **Hop classes** (`src/Result/Hop/`) — `WhoisHop` (server, query, rawText, info, error), `WhoisHttpHop` (extends WhoisHop), `RdapHop` (server, query, url, json, rawBody, info, error).

### Enums

- `QueryType` (`src/Enum/QueryType.php`) — Domain, Ipv4, Ipv6, Asn, NicHandle. Has `guess(string): self` for auto-detection.
- `QueryMode` (`src/QueryMode.php`) — PreferRdap, PreferWhois, RdapOnly, WhoisOnly, Both.
- `ContactType` (`src/Result/Info/Field/ContactType.php`) — Registrant, Admin, Tech, Abuse.

### Exception Hierarchy

All library exceptions implement `WhoeasyException` (marker interface).

- `ClientException` (base, extends RuntimeException)
  - `ClientRequestException` — carries server/query/rawBody context via fluent `with*()` methods
    - `ClientResponseException` — adds httpCode
    - `ClientNetworkException` (implements RetryableException)
      - `ClientConnectException`
        - `ProxyConnectException`
      - `ClientTimeoutException`
    - `CurlRequestException` — carries verbose curl log
- `NotFoundException`
- `RateLimitException` (implements RetryableException)
- `NotSupportedException`
- `NotScrapeableException`
- `InvalidArgumentException`
- `MissingRequirementsException`
- `ParserException` (`src/Parser/Exception/`)

### Design Decisions

- **Readonly value objects** — All result classes are `readonly class` with typed properties. No setters.
- **Universal parser over templates** — Single WhoisParser handles all servers via field normalization + RPSL object parsing. No per-server parser classes. Tested against stored fixtures.
- **RPSL object parsing** — IP/ASN WHOIS responses from RIPE/APNIC/LACNIC/AFRINIC use multi-object RPSL format. Parser splits into objects, resolves admin-c/tech-c/abuse-c/org cross-references. Falls back to flat ARIN-style parsing.
- **Generated registry data** — Server lookup tables are PHP arrays generated at build time from IANA/RIR sources. Opcache-friendly, no runtime network I/O for discovery.
- **Never throw on empty results** — Whoeasy always returns QueryResult even when info is null. Errors are attached to individual hops. Callers inspect via `isNotFound()`, `hasRetryableErrors()`, or hop-level `$hop->error`.
- **NotFound short-circuits prefer/both** — In PreferRdap/PreferWhois/Both modes, if the first protocol returns NotFound, the second protocol is not attempted (the domain definitively doesn't exist).
- **Subset-aware contact merging** — ResultMerger preserves multiple same-type contacts when they have conflicting fields. Only merges when one contact's non-null fields are all compatible with another's.
- **RetryableException marker** — Callers can catch `RetryableException` to implement retry logic without knowing specific exception types.
- **Fluent exception context** — `ClientRequestException` uses `->withServer()->withQuery()->withRawBody()` to attach diagnostic info without constructor bloat.

## Workflows

### Build (generate registry data)

```bash
php generator/update-sources.php    # download IANA/RIR source files
php generator/generate-registry.php # generate src/Registry/Data/*.php
```

### Collect fixtures

```bash
php generator/collect-whois-fixtures.php                  # fetch domain WHOIS responses
php generator/collect-whois-fixtures.php --filter=ipv4     # fetch IPv4 WHOIS responses
php generator/collect-whois-fixtures.php --filter=asn      # fetch ASN WHOIS responses
php generator/collect-rdap-fixtures.php                    # fetch domain RDAP responses
php generator/collect-rdap-fixtures.php --filter=ipv4      # fetch IPv4 RDAP responses
/generate-expected                                         # Claude skill: generate .expected.json
```

### Test

```bash
vendor/bin/phpunit                         # full PHPUnit suite
vendor/bin/phpunit tests/Unit/WhoisFixtureTest.php   # WHOIS parser fixtures only
vendor/bin/phpunit tests/Unit/Rdap/RdapParserTest.php  # RDAP parser fixtures only
vendor/bin/phpstan analyse                 # static analysis (level max)
php bin/whoeasy --help                     # verify CLI works
```

All code changes must pass both PHPUnit tests and PHPStan at level max before committing.

Fixtures are stored as raw responses + `.expected.json` sidecar files. Tests parse the raw response and compare against expected output. Expected files are generated by the `/generate-expected` Claude skill — it reads raw WHOIS/RDAP data and extracts structured data per `RESULT_FORMAT.md`.

### Fix parser

Use `/develop-parser` Claude skill to iteratively fix the WHOIS or RDAP parser until fixture tests pass. It runs the test loop, analyzes failures, applies minimal fixes, and re-runs.

## CLI

```
whoeasy [options] <domain|ip|asn>

Options:
  -s, --server <server>    use specified WHOIS server (not yet implemented)
  -p, --proxy <uri>        proxy address (SOCKS5/HTTP)
  -m, --mode <mode>        query mode (default: prefer-rdap)
  -r, --recursive          follow referrals [default]
      --no-recursive       do not follow referrals
  -F, --full               output full result with hops (default: info only)
  -v, --verbose            show info-level log output
  -vv, --debug             show debug-level log output (includes raw responses)
  -h, --help               show this message
```

## Conventions

- PHP 8.2+ strict_types, readonly classes, backed enums, named arguments
- No docblocks on self-documenting code. PHPDoc only for non-obvious contracts.
- Exceptions carry context (server, query, rawBody) — always attach when available.
- Fixture-based testing: one raw response file + one expected JSON per server/query combination.
- Query type detected from fixture filename: `ip-*` → IPv4, `ip6-*` → IPv6, `asn-*` → ASN, else → Domain.
