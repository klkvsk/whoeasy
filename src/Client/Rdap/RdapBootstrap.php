<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Rdap;

/**
 * IANA RDAP Bootstrap Service (RFC 7484).
 *
 * Resolves query inputs to RDAP base URLs using IANA's published bootstrap files.
 * Bootstrap data is fetched once and cached in memory for the lifetime of the object.
 */
class RdapBootstrap
{
    private const BOOTSTRAP_DOMAIN = 'https://data.iana.org/rdap/dns.json';
    private const BOOTSTRAP_IPV4 = 'https://data.iana.org/rdap/ipv4.json';
    private const BOOTSTRAP_IPV6 = 'https://data.iana.org/rdap/ipv6.json';
    private const BOOTSTRAP_ASN = 'https://data.iana.org/rdap/asn.json';

    /** @var array<string, array> Cached bootstrap data keyed by type */
    private array $cache = [];

    /**
     * @param int $fetchTimeout Timeout in seconds for fetching bootstrap files
     */
    public function __construct(
        private int $fetchTimeout = 10,
    ) {}

    /**
     * Find the RDAP base URL for a given query input.
     *
     * @param string $input The query input (domain, IP, or ASN number)
     * @param string $type One of: 'domain', 'ip', 'autnum'
     * @return string|null The RDAP base URL, or null if not found
     */
    public function findServer(string $input, string $type): ?string
    {
        return match ($type) {
            'domain' => $this->findDomainServer($input),
            'ip' => $this->findIpServer($input),
            'autnum' => $this->findAsnServer($input),
            default => null,
        };
    }

    private function findDomainServer(string $domain): ?string
    {
        $data = $this->fetchBootstrap(self::BOOTSTRAP_DOMAIN, 'domain');
        if ($data === null) {
            return null;
        }

        // Extract TLD from domain
        $parts = explode('.', rtrim(strtolower($domain), '.'));
        $tld = end($parts);

        // Try exact TLD match first, then walk up
        foreach ($data['services'] ?? [] as $service) {
            [$tlds, $urls] = $service;
            foreach ($tlds as $entry) {
                if (strtolower($entry) === $tld) {
                    return $this->pickUrl($urls);
                }
            }
        }

        return null;
    }

    private function findIpServer(string $ip): ?string
    {
        $isV6 = str_contains($ip, ':');
        $bootstrapUrl = $isV6 ? self::BOOTSTRAP_IPV6 : self::BOOTSTRAP_IPV4;
        $type = $isV6 ? 'ipv6' : 'ipv4';

        $data = $this->fetchBootstrap($bootstrapUrl, $type);
        if ($data === null) {
            return null;
        }

        $ipLong = $isV6 ? null : ip2long($ip);

        foreach ($data['services'] ?? [] as $service) {
            [$prefixes, $urls] = $service;
            foreach ($prefixes as $prefix) {
                if ($this->ipMatchesPrefix($ip, $prefix, $isV6, $ipLong)) {
                    return $this->pickUrl($urls);
                }
            }
        }

        return null;
    }

    private function findAsnServer(string $asn): ?string
    {
        $asnNum = (int) preg_replace('/^AS/i', '', $asn);
        $data = $this->fetchBootstrap(self::BOOTSTRAP_ASN, 'autnum');
        if ($data === null) {
            return null;
        }

        foreach ($data['services'] ?? [] as $service) {
            [$ranges, $urls] = $service;
            foreach ($ranges as $range) {
                if (str_contains($range, '-')) {
                    [$lo, $hi] = array_map('intval', explode('-', $range));
                    if ($asnNum >= $lo && $asnNum <= $hi) {
                        return $this->pickUrl($urls);
                    }
                } elseif ((int) $range === $asnNum) {
                    return $this->pickUrl($urls);
                }
            }
        }

        return null;
    }

    private function ipMatchesPrefix(string $ip, string $prefix, bool $isV6, ?int $ipLong): bool
    {
        if (!str_contains($prefix, '/')) {
            return false;
        }

        [$network, $bits] = explode('/', $prefix);
        $bits = (int) $bits;

        if ($isV6) {
            return $this->ipv6MatchesPrefix($ip, $network, $bits);
        }

        $networkLong = ip2long($network);
        if ($networkLong === false || $ipLong === null) {
            return false;
        }

        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
        return ($ipLong & $mask) === ($networkLong & $mask);
    }

    private function ipv6MatchesPrefix(string $ip, string $network, int $bits): bool
    {
        $ipBin = inet_pton($ip);
        $netBin = inet_pton($network);

        if ($ipBin === false || $netBin === false) {
            return false;
        }

        $fullBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        // Compare full bytes
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBin[$i] !== $netBin[$i]) {
                return false;
            }
        }

        // Compare remaining bits
        if ($remainingBits > 0 && $fullBytes < 16) {
            $mask = 0xFF << (8 - $remainingBits);
            if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($netBin[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Pick the preferred URL from a list of RDAP service URLs.
     * Prefers HTTPS over HTTP.
     */
    private function pickUrl(array $urls): ?string
    {
        $https = array_filter($urls, fn(string $u) => str_starts_with($u, 'https://'));
        return $https ? reset($https) : ($urls[0] ?? null);
    }

    /**
     * Fetch and cache a bootstrap file.
     */
    private function fetchBootstrap(string $url, string $cacheKey): ?array
    {
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $curl = curl_init($url);
        if (!$curl) {
            return null;
        }

        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->fetchTimeout,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_USERAGENT => 'whoeasy/2.0 (RDAP bootstrap)',
        ]);

        $body = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($httpCode !== 200 || !is_string($body)) {
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return null;
        }

        $this->cache[$cacheKey] = $data;
        return $data;
    }

    /**
     * Pre-load bootstrap data from a local array (useful for testing).
     */
    public function preloadCache(string $type, array $data): void
    {
        $this->cache[$type] = $data;
    }
}
