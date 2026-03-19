<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;
use Klkvsk\Whoeasy\Client\Exception\CurlRequestException;
use Klkvsk\Whoeasy\Client\Exception\ProxyConnectException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

/**
 * WHOIS protocol client using curl in telnet mode.
 *
 * Curl telnet allows plain-text TCP communication to port 43,
 * with native support for HTTP/SOCKS proxies via CURLOPT_PROXY.
 */
class WhoisClient implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected const DEFAULT_PORT = 43;

    public function __construct()
    {
        $this->logger = new NullLogger();
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('ext-curl is required for ' . self::class);
        }
    }

    /**
     * Query a WHOIS server and return the raw text response.
     *
     * @param string $server WHOIS server hostname (e.g., "whois.verisign-grs.com")
     * @param string $query  The query string (e.g., "example.com")
     * @param int $timeout Request timeout in seconds
     * @param string|null $queryFormat Optional query format string (e.g. "n + %s")
     * @param string|null $proxyUri Optional SOCKS5/HTTP proxy URI
     * @return string Raw WHOIS response text
     *
     * @throws ClientConnectException If connection to the server fails
     * @throws ClientTimeoutException If the connection or read times out
     * @throws CurlRequestException On curl-level errors
     */
    public function query(
        string $server,
        string $query,
        int $timeout = 15,
        ?string $queryFormat = null,
        ?string $proxyUri = null,
    ): string {
        $port = self::DEFAULT_PORT;

        // Parse server:port if specified
        if (str_contains($server, ':')) {
            $parts = explode(':', $server, 2);
            $server = $parts[0];
            $port = (int)$parts[1];
        }

        $queryFormatted = ($queryFormat !== null ? sprintf($queryFormat, $query) : $query);

        // remove auth data from proxyUri (e.g. socks5://user:pass@127.0.0.1:1080 or user:pass@127.0.0.1:1080)
        if ($proxyUri !== null) {
            $proxyUri = preg_replace('#(//|^)([^@]+@)?#', '', $proxyUri);
        }

        $this->logger?->info(
            'WHOIS query: "{query}" at {server}:{port}'
            . ($proxyUri ? ' using proxy {proxy}' : ''),
            [
                'server' => $server,
                'port' => $port,
                'query' => $query,
                'proxy' => $proxyUri,
            ],
        );

        // Prepare query input as a stream (curl reads from CURLOPT_INFILE for telnet)
        $input = fopen('php://temp', 'r+') ?: throw new \RuntimeException('Failed to open temp stream');
        fwrite($input, $queryFormatted . "\r\n");
        rewind($input);

        // Verbose log for diagnostics
        $verboseLog = fopen('php://temp', 'w+') ?: throw new \RuntimeException('Failed to open temp stream');

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_PROTOCOLS      => CURLPROTO_TELNET,
            CURLOPT_URL            => "telnet://$server:$port",
            CURLOPT_INFILE         => $input,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_VERBOSE        => true,
            CURLOPT_STDERR         => $verboseLog,
        ]);

        if ($proxyUri !== null) {
            curl_setopt($curl, CURLOPT_PROXY, $proxyUri);
        }

        try {
            $response = curl_exec($curl);
            $errno = curl_errno($curl);
            $error = curl_error($curl);

            if ($errno !== 0) {
                rewind($verboseLog);
                $log = stream_get_contents($verboseLog) ?: '';

                // Map curl error codes to typed exceptions
                if (in_array($errno, [CURLE_OPERATION_TIMEDOUT, CURLE_OPERATION_TIMEOUTED], true)) {
                    throw (new ClientTimeoutException("Timeout from $server:$port after {$timeout}s ($error)"))
                        ->withServer($server)
                        ->withQuery($query);
                }

                if (in_array($errno, [CURLE_COULDNT_CONNECT, CURLE_COULDNT_RESOLVE_HOST], true)) {
                    throw (new ClientConnectException("Failed to connect to $server:$port: $error"))
                        ->withServer($server)
                        ->withQuery($query);
                }

                // Proxy-related errors
                if (in_array($errno, [5, 7, 97], true) && $proxyUri !== null) {
                    throw (new ProxyConnectException("Proxy connection failed for $server:$port: $error"))
                        ->withServer($server)
                        ->withQuery($query);
                }

                throw (new CurlRequestException(
                    sprintf('%s (code %d)', $error, $errno),
                    $errno,
                    verboseLog: $log,
                ))
                    ->withServer($server)
                    ->withQuery($query);
            }

            if (!is_string($response)) {
                $response = '';
            }
        } finally {
            curl_close($curl);
            fclose($input);
            fclose($verboseLog);
        }

        // Convert encoding if needed (best-effort UTF-8)
        if (!mb_check_encoding($response, 'UTF-8')) {
            $response = mb_convert_encoding($response, 'UTF-8', 'ISO-8859-1');
        }

        $this->logger?->debug("WHOIS response from {server}:\n{response}", [
            'server' => $server,
            'response' => $response,
        ]);

        return $response;
    }

}
