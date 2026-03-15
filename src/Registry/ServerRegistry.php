<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Registry;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
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
    /** @var array<string, array<string, string>> Server -> QueryType->value -> format */
    private const QUERY_FORMATS = [
        'whois.arin.net' => [
            'ipv4' => 'n + %s',
            'ipv6' => 'n + %s',
        ],
        'whois.denic.de' => [
            'domain' => '-T dn %s',
        ],
        'whois.jprs.jp' => [
            'domain' => '%s/e',
        ],
    ];

    /** @var array<string, string> Original server -> replacement server */
    private const SERVER_REMAPS = [
        'whois.nic.ad.jp' => 'whois.apnic.net',
        'whois.twnic.net' => 'whois.apnic.net',
        'whois.nic.or.kr' => 'whois.apnic.net',
        // Remap to web version without captcha
        'grweb.ics.forth.gr' => 'www.innoview.gr',
        // Remap to web version, as port 43 times out
        'whois.tonic.to' => 'www.tonic.to',
    ];

    /**
     * HTTP-based WHOIS servers.
     * Maps whois server hostname -> [httpUrl, httpQueryFormat, scraperName|null]
     * @var array<string, array{0: string, 1: string, 2: ?string}>
     */
    private const HTTP_SERVERS = [
        'www.dnsbelgium.be' => ['https://api.dnsbelgium.be', 'GET /whois/registration/%s', null],
        'www.vnnic.vn' => ['https://whois.net.vn', 'GET /whois.php?domain=%s&act=getwhois', null],
        'www.tonic.to' => ['https://www.tonic.to', 'GET /whois?%s', null],
        'whois.nic.ch' => ['https://rdap.nic.ch', 'GET /domain/%s', 'ch'],
        'whois.dot.ph' => ['https://whois.dot.ph', 'GET /?search=%s', 'ph'],
        'www.nic.pa' => ['http://www.nic.pa', 'GET /en/whois/dominio/%s', 'pa'],
        'www.innoview.gr' => ['https://www.innoview.gr', 'POST /members/whoisdomain.php whoisdomainname=%s', 'gr'],
        'www.nic.tt' => ['https://www.nic.tt', 'POST /cgi-bin/search.pl name=%s', 'tt'],
        'www.nic.tj' => ['http://www.nic.tj', 'GET /cgi/whois2?domain=%s', 'tj'],
        'nic.com.uy' => ['https://nic.com.uy', 'NONE only-web', 'not-scrapeable'],
        'www.dominios.es' => ['https://nic.es', 'NONE only-web', 'not-scrapeable'],
        // Remapped server names from TLD registry
        'whois.nic.org.uy' => ['https://nic.com.uy', 'NONE only-web', 'not-scrapeable'],
        'whois.nic.es' => ['https://nic.es', 'NONE only-web', 'not-scrapeable'],
    ];

    /**
     * TLD-based overrides for servers not in the generated TLD data,
     * or where the TLD data has no whois server at all.
     * Maps TLD -> [whoisServer, httpUrl, httpQueryFormat, scraperName|null]
     * @var array<string, array{0: string, 1: string, 2: string, 3: ?string}>
     */
    private const TLD_HTTP_OVERRIDES = [
        '.vn' => ['www.vnnic.vn', 'https://whois.net.vn', 'GET /whois.php?domain=%s&act=getwhois', null],
    ];

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
     * @throws InvalidArgumentException If the query type cannot be determined or no server is found
     */
    public function resolve(string $query): ServerInfo
    {
        $queryType = QueryType::guess($query);

        $info = match ($queryType) {
            QueryType::Domain => $this->resolveDomain($query),
            QueryType::Ipv4 => $this->resolveIpv4($query),
            QueryType::Ipv6 => $this->resolveIpv6($query),
            QueryType::Asn => $this->resolveAsn($query),
        };

        return $this->applyCustomizations($info);
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

    private function applyCustomizations(ServerInfo $info): ServerInfo
    {
        $server = $info->whoisServer;

        // Apply server remaps
        if ($server !== null && isset(self::SERVER_REMAPS[$server])) {
            $server = self::SERVER_REMAPS[$server];
        }

        // Look up query format for this server + query type combination
        $queryFormat = null;
        if ($server !== null && isset(self::QUERY_FORMATS[$server][$info->queryType->value])) {
            $queryFormat = self::QUERY_FORMATS[$server][$info->queryType->value];
        }

        // Look up HTTP server configuration
        $httpUrl = null;
        $httpQueryFormat = null;
        $httpScraper = null;
        if ($server !== null && isset(self::HTTP_SERVERS[$server])) {
            [$httpUrl, $httpQueryFormat, $httpScraper] = self::HTTP_SERVERS[$server];
        }

        // Handle .tj special case: strip TLD from query in the format
        if ($server === 'www.nic.tj' && $info->queryType === QueryType::Domain) {
            $domainWithoutTld = preg_replace('/\.tj$/', '', $info->query);
            $httpQueryFormat = 'GET /cgi/whois2?domain=' . urlencode($domainWithoutTld);
        }

        // Return new instance only if something changed
        if ($server !== $info->whoisServer || $queryFormat !== null || $httpUrl !== null) {
            return new ServerInfo(
                queryType: $info->queryType,
                whoisServer: $server,
                rdapUrl: $info->rdapUrl,
                query: $info->query,
                queryFormat: $queryFormat,
                charset: $info->charset,
                httpUrl: $httpUrl,
                httpQueryFormat: $httpQueryFormat,
                httpScraper: $httpScraper,
            );
        }

        return $info;
    }

    private function resolveDomain(string $query): ServerInfo
    {
        $query = strtolower(trim($query, '.'));
        $parts = explode('.', $query);

        // Try progressively shorter suffixes: .co.uk -> .uk
        for ($i = 0; $i < count($parts); $i++) {
            $suffix = '.' . implode('.', array_slice($parts, $i));

            // Check TLD HTTP overrides first (for TLDs with no server in generated data)
            if (isset(self::TLD_HTTP_OVERRIDES[$suffix])) {
                [$whois, $httpUrl, $httpQueryFormat, $httpScraper] = self::TLD_HTTP_OVERRIDES[$suffix];
                return new ServerInfo(
                    queryType: QueryType::Domain,
                    whoisServer: $whois,
                    rdapUrl: null,
                    query: $query,
                    httpUrl: $httpUrl,
                    httpQueryFormat: $httpQueryFormat,
                    httpScraper: $httpScraper,
                );
            }

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

        throw new InvalidArgumentException("No server found for domain: $query");
    }

    private function resolveIpv4(string $query): ServerInfo
    {
        // Strip CIDR notation if present
        $ip = explode('/', $query)[0];
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            throw new InvalidArgumentException("Invalid IPv4 address: $query");
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

        throw new InvalidArgumentException("No server found for IPv4: $query");
    }

    private function resolveIpv6(string $query): ServerInfo
    {
        // Expand IPv6 and get the first 32 bits as a long
        $expanded = inet_pton($query);
        if ($expanded === false) {
            throw new InvalidArgumentException("Invalid IPv6 address: $query");
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

        throw new InvalidArgumentException("No server found for IPv6: $query");
    }

    private function resolveAsn(string $query): ServerInfo
    {
        $asnNumber = (int)preg_replace('/^(ASN?|autnum-?)/i', '', $query);
        if ($asnNumber <= 0) {
            throw new InvalidArgumentException("Invalid ASN: $query");
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

        throw new InvalidArgumentException("No server found for ASN: $query");
    }
}
