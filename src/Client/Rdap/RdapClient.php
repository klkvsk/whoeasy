<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Rdap;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

/**
 * RDAP client that queries RDAP servers over HTTP/HTTPS per RFC 7480/9083.
 */
class RdapClient
{
    private RdapBootstrap $bootstrap;

    public function __construct(
        private int $timeout = 15,
        private ?string $proxyUri = null,
        ?RdapBootstrap $bootstrap = null,
    ) {
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('Curl extension is required for RDAP');
        }
        $this->bootstrap = $bootstrap ?? new RdapBootstrap();
    }

    public function setTimeout(int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function setProxy(?string $proxyUri): static
    {
        $this->proxyUri = $proxyUri;
        return $this;
    }

    /**
     * Query RDAP for a domain name.
     *
     * @return RdapResponse The parsed RDAP response
     * @throws ClientException
     */
    public function queryDomain(string $domain): RdapResponse
    {
        $domain = rtrim(strtolower($domain), '.');
        $baseUrl = $this->bootstrap->findServer($domain, 'domain');

        if ($baseUrl === null) {
            throw new ClientException("No RDAP server found for domain: $domain");
        }

        $url = rtrim($baseUrl, '/') . '/domain/' . rawurlencode($domain);
        return $this->execute($url, $baseUrl);
    }

    /**
     * Query RDAP for an IP address (v4 or v6).
     *
     * @return RdapResponse The parsed RDAP response
     * @throws ClientException
     */
    public function queryIp(string $ip): RdapResponse
    {
        $baseUrl = $this->bootstrap->findServer($ip, 'ip');

        if ($baseUrl === null) {
            throw new ClientException("No RDAP server found for IP: $ip");
        }

        $url = rtrim($baseUrl, '/') . '/ip/' . rawurlencode($ip);
        return $this->execute($url, $baseUrl);
    }

    /**
     * Query RDAP for an Autonomous System Number.
     *
     * @return RdapResponse The parsed RDAP response
     * @throws ClientException
     */
    public function queryAsn(int $asn): RdapResponse
    {
        $baseUrl = $this->bootstrap->findServer((string) $asn, 'autnum');

        if ($baseUrl === null) {
            throw new ClientException("No RDAP server found for ASN: $asn");
        }

        $url = rtrim($baseUrl, '/') . '/autnum/' . $asn;
        return $this->execute($url, $baseUrl);
    }

    /**
     * Query a specific RDAP URL directly.
     *
     * @return RdapResponse The parsed RDAP response
     * @throws ClientException
     */
    public function queryUrl(string $url): RdapResponse
    {
        $parsed = parse_url($url);
        $server = ($parsed['scheme'] ?? 'https') . '://' . ($parsed['host'] ?? 'unknown');
        return $this->execute($url, $server);
    }

    /**
     * Execute an RDAP HTTP request and return structured response.
     *
     * @throws ClientException
     */
    private function execute(string $url, string $server): RdapResponse
    {
        $curl = curl_init();
        if (!$curl) {
            throw new ClientException('Unable to create cURL handler');
        }

        try {
            curl_setopt_array($curl, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_HTTPHEADER => [
                    'Accept: application/rdap+json, application/json',
                ],
                CURLOPT_USERAGENT => 'whoeasy/2.0 (RDAP client)',
            ]);

            if ($this->proxyUri !== null) {
                curl_setopt($curl, CURLOPT_PROXY, $this->proxyUri);
            }

            $body = curl_exec($curl);
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            $errno = curl_errno($curl);

            if ($errno || $error) {
                throw new ClientException("RDAP request failed: $error (code $errno)");
            }

            if ($httpCode === 404) {
                throw new NotFoundException("RDAP: nothing found at $url");
            }

            if ($httpCode === 429) {
                throw new RateLimitException("RDAP rate limit exceeded for $server");
            }

            if ($httpCode < 200 || $httpCode >= 300) {
                throw new ClientResponseException("RDAP server returned HTTP $httpCode for $url");
            }

            $json = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($json)) {
                throw new ClientResponseException("RDAP: invalid JSON response from $url");
            }

            return new RdapResponse(
                server: $server,
                url: $url,
                httpCode: $httpCode,
                json: $json,
                rawBody: $body,
            );
        } catch (\JsonException $e) {
            throw new ClientResponseException("RDAP: failed to parse JSON from $url: " . $e->getMessage());
        } finally {
            curl_close($curl);
        }
    }

    /**
     * Determine query type from input string (reuses WHOIS logic).
     */
    public static function guessQueryType(string $input): string
    {
        if (preg_match('/^asn?[0-9]+$/i', $input)) {
            return RequestInterface::QUERY_TYPE_ASN;
        }
        if (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return RequestInterface::QUERY_TYPE_IPV4;
        }
        if (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return RequestInterface::QUERY_TYPE_IPV6;
        }
        return RequestInterface::QUERY_TYPE_DOMAIN;
    }
}
