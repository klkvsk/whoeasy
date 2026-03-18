<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;
use Klkvsk\Whoeasy\Client\Exception\CurlRequestException;
use Klkvsk\Whoeasy\Client\Exception\ProxyConnectException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

/**
 * WHOIS protocol client using curl in telnet mode.
 *
 * Curl telnet allows plain-text TCP communication to port 43,
 * with native support for HTTP/SOCKS proxies via CURLOPT_PROXY.
 */
final class WhoisClient
{
    private const DEFAULT_PORT = 43;

    public function __construct(
        private int $timeout = 15,
        private ?string $proxyUri = null,
    ) {
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('ext-curl is required for ' . self::class);
        }
    }

    /**
     * Query a WHOIS server and return the raw text response.
     *
     * @param string $server WHOIS server hostname (e.g., "whois.verisign-grs.com")
     * @param string $query  The query string (e.g., "example.com")
     * @param int|null $timeout Override timeout for this request
     * @return string Raw WHOIS response text
     *
     * @throws ClientConnectException If connection to the server fails
     * @throws ClientTimeoutException If the connection or read times out
     * @throws CurlRequestException On curl-level errors
     */
    public function query(string $server, string $query, ?int $timeout = null, ?string $queryFormat = null): string
    {
        $timeout ??= $this->timeout;
        $port = self::DEFAULT_PORT;

        // Parse server:port if specified
        if (str_contains($server, ':')) {
            $parts = explode(':', $server, 2);
            $server = $parts[0];
            $port = (int)$parts[1];
        }

        // Prepare query input as a stream (curl reads from CURLOPT_INFILE for telnet)
        $queryLine = ($queryFormat !== null ? sprintf($queryFormat, $query) : $query) . "\r\n";
        $input = fopen('php://temp', 'r+');
        fwrite($input, $queryLine);
        rewind($input);

        // Verbose log for diagnostics
        $verboseLog = fopen('php://temp', 'w+');

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

        if ($this->proxyUri !== null) {
            curl_setopt($curl, CURLOPT_PROXY, $this->proxyUri);
        }

        try {
            $response = curl_exec($curl);
            $errno = curl_errno($curl);
            $error = curl_error($curl);

            if ($errno !== 0) {
                rewind($verboseLog);
                $log = stream_get_contents($verboseLog);

                // Map curl error codes to typed exceptions
                if (in_array($errno, [CURLE_OPERATION_TIMEDOUT, CURLE_OPERATION_TIMEOUTED ?? 28], true)) {
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
                if (in_array($errno, [5, 7, 97], true) && $this->proxyUri !== null) {
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

            if ($response === false) {
                $response = '';
            }
        } finally {
            curl_close($curl);
            fclose($input);
            fclose($verboseLog);
        }

        // Convert encoding if needed (best-effort UTF-8)
        if (!mb_check_encoding($response, 'UTF-8')) {
            $converted = mb_convert_encoding($response, 'UTF-8', 'ISO-8859-1');
            if ($converted !== false) {
                $response = $converted;
            }
        }

        return $response;
    }

    /**
     * Strip legal boilerplate, comment lines, and informational banners from raw WHOIS text.
     * Returns only the data-bearing portion of the response.
     */
    public static function stripBoilerplate(string $response): string
    {
        // Normalize line endings
        $response = str_replace("\r\n", "\n", $response);
        $response = str_replace("\r", "\n", $response);

        // Remove >>> marker lines (VeriSign/Identity Digital/Afilias boundary)
        // Don't truncate everything after it, as some servers (e.g., .st) include
        // detailed data in a second section after the marker
        $response = preg_replace('/^>>>.*<<<\s*$/m', '', $response);

        // Strip trailing legal blocks that appear without >>> marker
        $boilerplateStarts = [
            '/^NOTICE:\s/m',
            '/^Terms of Use:\s/m',
            '/^URL of the ICANN\b/m',
            '/^For more information on Whois status codes/m',
            '/^TERMS OF USE:\s/m',
        ];
        foreach ($boilerplateStarts as $pattern) {
            if (preg_match($pattern, $response, $m, \PREG_OFFSET_CAPTURE)) {
                $response = substr($response, 0, $m[0][1]);
            }
        }

        // Remove comment-prefixed lines (%, #, ;)
        $lines = explode("\n", $response);
        $cleaned = [];
        foreach ($lines as $line) {
            $trimmed = ltrim($line);
            if ($trimmed === '') {
                $cleaned[] = $line;
                continue;
            }
            if ($trimmed[0] === '%' || $trimmed[0] === ';') {
                continue;
            }
            // Strip #-prefixed comment lines, but preserve Korean WHOIS section headers
            if ($trimmed[0] === '#' && !preg_match('/^#\s*(ENGLISH|KOREAN)/i', $trimmed)) {
                continue;
            }
            $cleaned[] = $line;
        }

        return implode("\n", $cleaned);
    }

    /**
     * Detect referral server from WHOIS response text.
     *
     * Looks for patterns like:
     * - "Registrar WHOIS Server: whois.example.com"
     * - "refer: whois.example.com"
     * - "ReferralServer: whois://whois.example.com"
     */
    public static function detectReferral(string $response): ?string
    {
        $patterns = [
            '/^\s*Registrar WHOIS Server:\s*(.+)/mi',
            '/^\s*Whois Server:\s*(.+)/mi',
            '/^\s*refer:\s*(.+)/mi',
            '/^\s*ReferralServer:\s*(.+)/mi',
            '/^\s*Registrar Whois:\s*(.+)/mi',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response, $m)) {
                $referral = trim($m[1]);

                // Strip protocol prefix if present
                $referral = preg_replace('#^(whois|rwhois)://#i', '', $referral);

                // Strip port suffix and path
                $referral = preg_replace('#[:/].*$#', '', $referral);

                // Validate it looks like a hostname
                if (preg_match('/^[a-z0-9]([a-z0-9\-.]+[a-z0-9])?$/i', $referral)) {
                    return $referral;
                }
            }
        }

        return null;
    }

    /**
     * Detect if the response indicates rate limiting.
     */
    public static function isRateLimited(string $response): bool
    {
        $patterns = [
            '/(reached|exceeded) the maximum allowable/i',
            '/(reached|exceeded) your (query|request) limit/i',
            '/(rate limit|quota) (exceeded|reached)/i',
            '/try again (later|after)/i',
            '/(request|rate|query|connection) limit (exceeded|reached)/i',
            '/too many (requests|queries|lookups)/i',
            '/server is busy/i',
            '/(?<!for )excessive querying/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect if the response indicates the TLD/protocol is not supported by this server.
     */
    public static function isNotSupported(string $response): bool
    {
        $patterns = [
            '/^TLD is not supported\b/im',
            '/^This TLD has no whois server/im',
            '/^No whois service is available/im',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect if the response indicates "not found".
     */
    public static function isNotFound(string $response): bool
    {
        $patterns = [
            '/^[\W\s]*(no match|not found|no data found|nothing found|no domain|no information)/im',
            '/is available for registration/i',
            '/queried (object|domain|record) does not exist/i',
            '/domain is available/i',
            '/domain( name)? not found/i',
            '/^status: (free|available)/mi',
            '/no matching objects found/i',
            '/(objects?|domains?|records?|entry|entries) not found/im',
            '/(object|domain|key) does not exist/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

}
