<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Rdap;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;
use Klkvsk\Whoeasy\Registry\QueryType;

/**
 * RDAP client that queries RDAP servers over HTTP/HTTPS per RFC 7480/9083.
 *
 * Returns raw JSON arrays. The caller is responsible for parsing.
 */
class RdapClient
{
    public function __construct(
        private int $timeout = 15,
        private ?string $proxyUri = null,
    ) {
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('Curl extension is required for RDAP');
        }
    }

    /**
     * Query an RDAP server.
     *
     * @param string $rdapBaseUrl RDAP base URL (e.g., "https://rdap.verisign.com/com/v1/")
     * @param string $query The query input (domain name, IP address, or ASN like "AS15169")
     * @param QueryType|null $queryType Type of query; if null, guessed from $query
     * @return array Decoded JSON response
     */
    public function query(string $rdapBaseUrl, string $query, ?QueryType $queryType = null): array
    {
        return $this->queryUrl($this->createUrl($rdapBaseUrl, $query, $queryType));
    }

    /**
     * Create RDAP URL for a query.
     *
     * @param string $rdapBaseUrl RDAP base URL (e.g., "https://rdap.verisign.com/com/v1/")
     * @param string $query The query input (domain name, IP address, or ASN like "AS15169")
     * @param QueryType|null $queryType Type of query; if null, guessed from $query
     * @return string RDAP URL
     */
    public function createUrl(string $rdapBaseUrl, string $query, ?QueryType $queryType = null): string
    {
        $queryType ??= QueryType::guess($query);

        $path = match ($queryType) {
            QueryType::Domain => '/domain/' . rawurlencode(rtrim(strtolower($query), '.')),
            QueryType::Ipv4, QueryType::Ipv6 => '/ip/' . rawurlencode($query),
            QueryType::Asn => '/autnum/' . (int) preg_replace('/^(ASN?|autnum-?)/i', '', $query),
            QueryType::NicHandle => '/entity/' . rawurlencode($query),
        };

        return rtrim($rdapBaseUrl, '/') . $path;
    }

    /**
     * Query a specific RDAP URL directly
     *
     * @return array Decoded JSON response
     */
    public function queryUrl(string $url): array
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

            if ($httpCode < 200 || $httpCode >= 500) {
                throw (new ClientResponseException("RDAP server returned HTTP $httpCode for $url"))
                    ->withRawBody($body ?: '')
                    ->withHttpCode($httpCode);
            }

            $json = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($json)) {
                throw (new ClientResponseException("RDAP: invalid JSON response from $url"))
                    ->withRawBody($body ?: '')
                    ->withHttpCode($httpCode);
            }

            return $json;
        } catch (\JsonException $e) {
            throw new ClientResponseException("RDAP: failed to parse JSON from $url: " . $e->getMessage());
        } finally {
            curl_close($curl);
        }
    }
}
