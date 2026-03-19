# Whoeasy
![README-logo.png](README-logo.png)
[![Packagist Version](https://img.shields.io/packagist/v/klkvsk/whoeasy)](https://packagist.org/packages/klkvsk/whoeasy)
[![PHP Version](https://img.shields.io/packagist/dependency-v/klkvsk/whoeasy/php)](https://packagist.org/packages/klkvsk/whoeasy)
[![License](https://img.shields.io/packagist/l/klkvsk/whoeasy)](https://github.com/klkvsk/whoeasy/blob/master/LICENSE)

Smart WHOIS + RDAP client and parser for PHP. Lookup domain names, IP addresses and AS numbers. Get structured, typed results from both WHOIS (RFC 3912) and RDAP (RFC 7480/9083) protocols with automatic server discovery, referral following, and result merging.

## Features

- **Dual protocol** — queries both WHOIS and RDAP, merges results for maximum coverage
- **Auto-detection** — recognizes domains, IPv4/IPv6 addresses, and AS numbers from input
- **Typed results** — readonly `DomainInfo`, `IpInfo`, `AsnInfo` value objects with `toArray()` support
- **Referral following** — automatically follows WHOIS referrals and RDAP redirects
- **5 query modes** — prefer RDAP, prefer WHOIS, RDAP-only, WHOIS-only, or both
- **Proxy support** — SOCKS5 and HTTP proxies via curl
- **CLI tool** — `vendor/bin/whoeasy` for quick lookups with JSON output
- **No runtime network I/O for server discovery** — pre-generated registry from IANA/RIR sources

## Installation

```bash
composer require klkvsk/whoeasy
```

**Requirements:** PHP 8.2+, ext-mbstring

**Recommended:** ext-curl (required for RDAP; WHOIS falls back to sockets without it)

## Quick Start

```php
use Klkvsk\Whoeasy\Whoeasy;

$whoeasy = Whoeasy::create();

// Domain lookup
$result = $whoeasy->domain('example.com');
echo $result->info->registrar->name;       // e.g. "RESERVED-Internet Assigned Numbers Authority"
echo $result->info->expiresDate;           // e.g. "2025-08-13 04:00:00"
echo $result->info->nameservers[0]->hostname; // e.g. "a.iana-servers.net"

// IP lookup
$result = $whoeasy->ip('8.8.8.8');
echo $result->info->networkName;  // e.g. "GOGL"
echo $result->info->country;     // e.g. "US"

// ASN lookup
$result = $whoeasy->asn('AS15169');
echo $result->info->name;         // e.g. "GOOGLE"
echo $result->info->description;  // e.g. "Google LLC"

// Auto-detect query type
$result = $whoeasy->query('example.com');
```

## Error Handling

Whoeasy never throws on empty results. Errors are attached to individual protocol hops.

```php
$result = $whoeasy->query('nonexistent-domain.example');

if ($result->isNotFound()) {
    echo "Domain not found";
}

if ($result->info === null && $result->hasRetryableErrors()) {
    echo "Temporary error (rate limit, timeout) — retry later";
}

if ($result->info === null) {
    // Inspect hop-level errors for diagnostics
    foreach ($result->whois?->hops ?? [] as $hop) {
        if ($hop->error) {
            echo "WHOIS error: " . $hop->error->getMessage();
        }
    }
}
```

## Query Modes

| Mode | Enum value | Behavior |
|------|-----------|----------|
| **Prefer RDAP** (default) | `QueryMode::PreferRdap` | Try RDAP first, fall back to WHOIS on failure |
| **Prefer WHOIS** | `QueryMode::PreferWhois` | Try WHOIS first, fall back to RDAP on failure |
| **RDAP only** | `QueryMode::RdapOnly` | RDAP only, no WHOIS fallback |
| **WHOIS only** | `QueryMode::WhoisOnly` | WHOIS only, no RDAP |
| **Both** | `QueryMode::Both` | Query both protocols, merge results (RDAP priority) |

```php
use Klkvsk\Whoeasy\QueryMode;
use Klkvsk\Whoeasy\QueryOptions;

$result = $whoeasy->domain('example.com', new QueryOptions(
    mode: QueryMode::Both,
));
```

## Options

`QueryOptions` is a readonly class — pass it to `Whoeasy::create()` as defaults or per-query.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `QueryMode` | `PreferRdap` | Protocol selection strategy |
| `proxyUri` | `?string` | `null` | SOCKS5 or HTTP proxy URI |
| `whoisTimeout` | `int` | `15` | WHOIS request timeout in seconds |
| `rdapTimeout` | `int` | `15` | RDAP request timeout in seconds |
| `recursive` | `bool` | `true` | Follow referrals to authoritative servers |
| `maxReferrals` | `int` | `3` | Maximum referral hops to follow |

```php
// Set defaults for all queries
$whoeasy = Whoeasy::create(new QueryOptions(
    proxyUri: 'socks5://127.0.0.1:1080',
    whoisTimeout: 10,
    mode: QueryMode::WhoisOnly,
));

// Override per query
$result = $whoeasy->domain('example.com', new QueryOptions(
    mode: QueryMode::Both,
));
```

## Result Structure

All info classes are `readonly` with typed properties and a `toArray()` method.

**DomainInfo** — `name`, `registrar` (Registrar), `createdDate`, `updatedDate`, `expiresDate`, `status[]`, `nameservers[]` (Nameserver), `contacts[]` (Contact), `dnssec`

**IpInfo** — `range`, `networkName`, `description`, `asNumber`, `country`, `createdDate`, `updatedDate`, `status[]`, `contacts[]` (Contact)

**AsnInfo** — `asn`, `name`, `description`, `country`, `createdDate`, `updatedDate`, `status[]`, `contacts[]` (Contact)

**Registrar** — `name`, `ianaId`, `url`, `abuseEmail`, `abusePhone`

**Nameserver** — `hostname`, `ipv4`, `ipv6`

**Contact** — `type` (ContactType enum: Registrant/Admin/Tech/Abuse), `name`, `organization`, `email`, `phone`, `fax`, `address`

All dates are formatted as `"Y-m-d H:i:s"`. Nullable fields return `null` when data is unavailable.

```php
// Convert to array for serialization
$array = $result->info->toArray();
$json = json_encode($result->toArray(), JSON_PRETTY_PRINT);
```

## Accessing Raw Data

`QueryResult` contains protocol-level details through hops:

```php
$result = $whoeasy->domain('example.com', new QueryOptions(
    mode: QueryMode::Both,
));

// Raw WHOIS text from each server in the referral chain
foreach ($result->whois?->hops ?? [] as $hop) {
    echo "Server: {$hop->server}\n";
    echo $hop->response . "\n\n";
}

// Raw RDAP JSON
foreach ($result->rdap?->hops ?? [] as $hop) {
    echo "URL: {$hop->url}\n";
    echo $hop->response . "\n";    // raw JSON string
    print_r($hop->json);           // decoded JSON array
}
```

## CLI

```
vendor/bin/whoeasy [options] <domain|ip|asn>
```

| Option | Description |
|--------|-------------|
| `-m, --mode <mode>` | Query mode: `prefer-rdap` (default), `prefer-whois`, `rdap-only`, `whois-only`, `both` |
| `-p, --proxy <uri>` | Proxy address (SOCKS5 or HTTP) |
| `-r, --recursive` | Follow referrals (default) |
| `--no-recursive` | Do not follow referrals |
| `-F, --full` | Output full result with hops (default: info only) |
| `-v, --verbose` | Show debug output and traces |
| `-h, --help` | Show help message |

```bash
# Domain lookup (JSON output)
vendor/bin/whoeasy example.com

# IP lookup with WHOIS only
vendor/bin/whoeasy -m whois-only 8.8.8.8

# Full result with all hops through a proxy
vendor/bin/whoeasy --full -p socks5://127.0.0.1:1080 AS15169
```

You can also run whoeasy without installing it as a dependency using [cpx](https://github.com/php-cpx/cpx):

```bash
cpx klkvsk/whoeasy example.com
```

## What's New in v2

- **RDAP support** — full RFC 9083 parsing for domains, IPs, and AS numbers
- **Dual-protocol merging** — 5 query modes with intelligent result merging (RDAP priority for scalars, combined+deduplicated arrays)
- **New entry point** — `Whoeasy::create()` replaces the old `Whois` class
- **Typed result objects** — readonly `DomainInfo`, `IpInfo`, `AsnInfo` with typed properties instead of generic arrays
- **Referral chain visibility** — full hop history with raw data and per-hop errors
- **Universal WHOIS parser** — single parser handles all known TLDs via field normalization and RPSL object parsing; replaces Novutec template system
- **Error model overhaul** — never throws on empty results; `isNotFound()`, `hasRetryableErrors()` inspection methods; `RetryableException` marker interface
- **CLI rewrite** — JSON output, `--mode`, `--full`, `--proxy`, `--no-recursive` options

## Data Sources

Server registry data is generated at build time from:
- [IANA bootstrap registries](https://www.iana.org/) — RDAP server assignments for domains, IPv4, IPv6, ASN
- [rfc1036/whois](https://github.com/rfc1036/whois) — WHOIS server assignments (same source as the Linux `whois` tool)
- [whoisserver.world](https://whoisserver-world.org/) — WHOIS/RDAP server assignments and sample domains per TLD
- [resolve.rs](https://resolve.rs/) — supplementary TLD coverage

The generated PHP arrays are stored in `src/Registry/Data/` and loaded via opcache with no runtime network I/O for server discovery.

## Testing

The parser is tested against stored fixtures — raw WHOIS/RDAP responses paired with `.expected.json` files containing the expected parsed output.

```bash
vendor/bin/phpunit
vendor/bin/phpstan analyse
```

- 260+ WHOIS fixtures across domains, IPs, and ASNs
- 35+ RDAP fixtures for domains, IPs, and ASNs
- Expected outputs validated against raw data
- PHPStan at level max for static analysis

## Contributing

Issues and pull requests welcome at [github.com/klkvsk/whoeasy](https://github.com/klkvsk/whoeasy).

**Fixture workflow:**
1. Add raw WHOIS/RDAP response files to `tests/Fixture/`
2. Generate `.expected.json` sidecar files (use the `/generate-expected` Claude skill)
3. Run `vendor/bin/phpunit` to verify parsing
4. If tests fail, use the `/develop-parser` Claude skill to iteratively fix the parser

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
