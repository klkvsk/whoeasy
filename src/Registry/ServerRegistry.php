<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Registry;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Exception\UnsupportedQueryException;
use Klkvsk\Whoeasy\Registry\Data\AsnRanges;
use Klkvsk\Whoeasy\Registry\Data\Ipv4Ranges;
use Klkvsk\Whoeasy\Registry\Data\Ipv6Ranges;
use Klkvsk\Whoeasy\Registry\Data\TldServers;

/**
 * Server registry for resolving queries to WHOIS/RDAP server info.
 *
 * Uses generated data arrays for fast lookups.
 */
final class ServerRegistry
{
    /** @var array<string, array{0: ?string, 1: ?string}> */
    private array $tldServers;

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $ipv4Ranges;

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $ipv6Ranges;

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $asnRanges;

    private static ?self $instance = null;

    public static function getInstance(): self
    {
        return self::$instance ??= new self();
    }

    public function __construct(
        ?array $tldServers = null,
        ?array $ipv4Ranges = null,
        ?array $ipv6Ranges = null,
        ?array $asnRanges = null,
    ) {
        $this->tldServers = $tldServers ?? TldServers::data();
        $this->ipv4Ranges = $ipv4Ranges ?? Ipv4Ranges::data();
        $this->ipv6Ranges = $ipv6Ranges ?? Ipv6Ranges::data();
        $this->asnRanges = $asnRanges ?? AsnRanges::data();
    }

    /**
     * Resolve a query string to server information.
     *
     * @return ServerInfo Server info with WHOIS and/or RDAP endpoints
     * @throws UnsupportedQueryException If the query type cannot be determined or no server is found
     */
    public function resolve(string $query): ServerInfo
    {
        $queryType = self::detectQueryType($query);

        return match ($queryType) {
            QueryType::Domain => $this->resolveDomain($query),
            QueryType::Ipv4 => $this->resolveIpv4($query),
            QueryType::Ipv6 => $this->resolveIpv6($query),
            QueryType::Asn => $this->resolveAsn($query),
        };
    }

    /**
     * Detect the query type from the input string.
     */
    public static function detectQueryType(string $query): QueryType
    {
        $query = trim($query);

        // ASN: AS followed by digits
        if (preg_match('/^AS\d+$/i', $query)) {
            return QueryType::Asn;
        }

        // IPv4: dotted decimal
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return QueryType::Ipv4;
        }

        // IPv6: colon-separated hex
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return QueryType::Ipv6;
        }

        // IPv4 CIDR notation
        if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $query)) {
            return QueryType::Ipv4;
        }

        // Domain: anything with a dot and valid characters
        if (preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/i', $query)) {
            return QueryType::Domain;
        }

        // Internationalized domain (starts with xn-- or contains non-ASCII)
        if (preg_match('/\.(xn--[a-z0-9]+|[^\x00-\x7f]+)$/i', $query)) {
            return QueryType::Domain;
        }

        throw new UnsupportedQueryException("Cannot determine query type for: $query");
    }

    /**
     * Look up TLD information directly.
     *
     * @return array{0: ?string, 1: ?string}|null [whois_server, rdap_url] or null
     */
    public function lookupTld(string $tld): ?array
    {
        $tld = strtolower($tld);
        if (!str_starts_with($tld, '.')) {
            $tld = '.' . $tld;
        }
        return $this->tldServers[$tld] ?? null;
    }

    /**
     * Get all TLD entries.
     *
     * @return array<string, array{0: ?string, 1: ?string}>
     */
    public function getAllTlds(): array
    {
        return $this->tldServers;
    }

    private function resolveDomain(string $query): ServerInfo
    {
        $query = strtolower(trim($query, '.'));
        $parts = explode('.', $query);

        // Try progressively shorter suffixes: .co.uk -> .uk
        for ($i = 0; $i < count($parts); $i++) {
            $suffix = '.' . implode('.', array_slice($parts, $i));
            if (isset($this->tldServers[$suffix])) {
                [$whois, $rdap] = $this->tldServers[$suffix];
                return new ServerInfo(
                    queryType: QueryType::Domain,
                    whoisServer: $whois,
                    rdapUrl: $rdap,
                    query: $query,
                );
            }
        }

        throw new UnsupportedQueryException("No server found for domain: $query");
    }

    private function resolveIpv4(string $query): ServerInfo
    {
        // Strip CIDR notation if present
        $ip = explode('/', $query)[0];
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            throw new UnsupportedQueryException("Invalid IPv4 address: $query");
        }

        foreach ($this->ipv4Ranges as [$rangeIp, $rangeMask, $server, $rdap]) {
            if (($ipLong & $rangeMask) === ($rangeIp & $rangeMask)) {
                return new ServerInfo(
                    queryType: QueryType::Ipv4,
                    whoisServer: $server,
                    rdapUrl: $rdap,
                    query: $query,
                );
            }
        }

        throw new UnsupportedQueryException("No server found for IPv4: $query");
    }

    private function resolveIpv6(string $query): ServerInfo
    {
        // Expand IPv6 and get the first 32 bits as a long
        $expanded = inet_pton($query);
        if ($expanded === false) {
            throw new UnsupportedQueryException("Invalid IPv6 address: $query");
        }

        // Get first 4 bytes as unsigned long
        $bytes = unpack('N', substr($expanded, 0, 4));
        $ipLong = $bytes[1];

        foreach ($this->ipv6Ranges as [$rangeIp, $rangeMask, $server, $rdap]) {
            if (($ipLong & $rangeMask) === ($rangeIp & $rangeMask)) {
                return new ServerInfo(
                    queryType: QueryType::Ipv6,
                    whoisServer: $server,
                    rdapUrl: $rdap,
                    query: $query,
                );
            }
        }

        throw new UnsupportedQueryException("No server found for IPv6: $query");
    }

    private function resolveAsn(string $query): ServerInfo
    {
        $asnNumber = (int)preg_replace('/^AS/i', '', $query);
        if ($asnNumber <= 0) {
            throw new UnsupportedQueryException("Invalid ASN: $query");
        }

        // Linear scan to find the most specific (smallest) matching range
        $bestMatch = null;
        $bestSize = PHP_INT_MAX;

        foreach ($this->asnRanges as [$start, $end, $server, $rdap]) {
            if ($asnNumber >= $start && $asnNumber <= $end) {
                $size = $end - $start;
                if ($size < $bestSize) {
                    $bestSize = $size;
                    $bestMatch = [$server, $rdap];
                }
            }
        }

        if ($bestMatch !== null) {
            return new ServerInfo(
                queryType: QueryType::Asn,
                whoisServer: $bestMatch[0],
                rdapUrl: $bestMatch[1],
                query: $query,
            );
        }

        throw new UnsupportedQueryException("No server found for ASN: $query");
    }
}
