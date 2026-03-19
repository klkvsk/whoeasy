<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

/**
 * HTTP-based WHOIS client using ext-curl.
 *
 * Handles WHOIS servers that expose data via HTTP endpoints
 * rather than the standard TCP:43 protocol.
 */
class HttpWhoisClient implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct()
    {
        $this->logger = new NullLogger();
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('ext-curl is required for HTTP WHOIS queries');
        }
    }

    /**
     * Query an HTTP-based WHOIS endpoint.
     *
     * @param string $httpUrl Base URL (e.g., "https://api.dnsbelgium.be")
     * @param string $query The domain/IP to look up
     * @param string $httpQueryFormat Format string like "GET /path/%s" or "POST /path field=%s"
     * @param string|null $scraperName Scraper name to process the response, or null for raw text
     * @param int $timeout Request timeout in seconds
     * @param string|null $proxyUri Optional SOCKS5/HTTP proxy URI
     * @return string Raw WHOIS text (scraped if scraper is configured)
     */
    public function query(
        string $httpUrl,
        string $query,
        string $httpQueryFormat,
        ?string $scraperName = null,
        int $timeout = 15,
        ?string $proxyUri = null,
    ): string {

        // Parse the query format: "GET /path/%s" or "POST /path body=%s"
        [$method, $rest] = $this->parseQueryFormat($httpQueryFormat, $query);

        if ($method === 'POST' || $method === 'JSON-POST') {
            // For POST: "POST /path body=%s" -> path and body are separated by space
            $parts = explode(' ', $rest, 2);
            $path = $parts[0];
            $body = $parts[1] ?? '';
            $url = rtrim($httpUrl, '/') . $path;
        } else {
            // For GET: path includes query string
            $url = rtrim($httpUrl, '/') . $rest;
            $body = null;
        }

        $this->logger?->info('HTTP WHOIS request: {method} {url}', [
            'method' => $method,
            'url' => $url,
        ]);

        $responseBody = $this->executeRequest($url, $method, $body, $timeout, $proxyUri);

        $this->logger?->debug("HTTP WHOIS response from {url}:\n{response}", [
            'url' => $url,
            'response' => $responseBody,
        ]);

        // Apply scraper if specified
        if ($scraperName !== null) {
            $responseBody = HttpScraper::process($scraperName, $responseBody);
        }

        return $responseBody;
    }

    /**
     * Parse HTTP query format string into method and path/body.
     *
     * @return array{0: string, 1: string} [method, rest]
     */
    private function parseQueryFormat(string $format, string $query): array
    {
        // Check if format already has the query baked in (e.g., .tj special case)
        if (!str_contains($format, '%s')) {
            // Format is pre-built, extract method and path
            if (preg_match('/^(GET|POST|JSON-POST)\s+(.+)$/i', $format, $m)) {
                return [strtoupper($m[1]), $m[2]];
            }
            throw new ClientRequestException("Invalid HTTP query format: $format");
        }

        // Standard format: "GET /path/%s", "POST /path field=%s", or "JSON-POST /path {...}"
        if (preg_match('/^(GET|POST|JSON-POST)\s+(.+)$/i', $format, $m)) {
            $method = strtoupper($m[1]);
            $pathTemplate = $m[2];
            // JSON-POST: don't urlencode the query — it goes into a JSON body template
            $resolved = $method === 'JSON-POST'
                ? sprintf($pathTemplate, $query)
                : sprintf($pathTemplate, urlencode($query));
            return [$method, $resolved];
        }

        throw new ClientRequestException("Invalid HTTP query format: $format");
    }

    /**
     * Execute the HTTP request using curl.
     */
    private function executeRequest(string $url, string $method, ?string $body, int $timeout, ?string $proxyUri = null): string
    {
        assert($url !== '');
        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_USERAGENT => 'Whoeasy/2.0 (https://github.com/klkvsk/whoeasy)',
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        if ($method === 'POST' || $method === 'JSON-POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                $contentType = $method === 'JSON-POST'
                    ? 'Content-Type: application/json'
                    : 'Content-Type: application/x-www-form-urlencoded';
                curl_setopt($ch, CURLOPT_HTTPHEADER, [$contentType]);
            }
        }

        if ($proxyUri !== null) {
            curl_setopt($ch, CURLOPT_PROXY, $proxyUri);
        }

        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if (!is_string($response)) {
            $host = parse_url($url, PHP_URL_HOST);
            $server = is_string($host) ? $host : $url;
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw (new ClientTimeoutException("HTTP request timed out after {$timeout}s: $url"))
                    ->withServer($server);
            }
            if ($errno === CURLE_COULDNT_CONNECT || $errno === CURLE_COULDNT_RESOLVE_HOST) {
                throw (new ClientConnectException("HTTP connection failed: $error"))
                    ->withServer($server);
            }
            throw new ClientRequestException("HTTP request failed: [$errno] $error");
        }

        return $response;
    }
}
