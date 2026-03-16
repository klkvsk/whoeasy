<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;

/**
 * WHOIS protocol client using TCP:43 stream sockets.
 *
 * Does NOT depend on v1 adapters. Uses PHP stream functions directly.
 */
final class WhoisClient
{
    private const DEFAULT_PORT = 43;
    private const READ_BUFFER_SIZE = 4096;

    public function __construct(
        private int $timeout = 15,
        private ?string $proxyUri = null,
    ) {
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

        $socket = $this->connect($server, $port, $timeout);

        try {
            // Send query followed by CRLF (RFC 3912)
            $queryLine = ($queryFormat !== null ? sprintf($queryFormat, $query) : $query) . "\r\n";
            $written = @fwrite($socket, $queryLine);
            if ($written === false || $written !== strlen($queryLine)) {
                throw (new ClientConnectException("Failed to send query to $server"))
                    ->withServer($server)
                    ->withQuery($query);
            }

            // Read response
            $response = '';
            while (!feof($socket)) {
                $chunk = @fread($socket, self::READ_BUFFER_SIZE);
                if ($chunk === false) {
                    $info = stream_get_meta_data($socket);
                    if ($info['timed_out'] ?? false) {
                        throw (new ClientTimeoutException("Read timeout from $server after {$timeout}s"))
                            ->withServer($server)
                            ->withQuery($query)
                            ->withRawBody($response);
                    }
                    break;
                }
                $response .= $chunk;

                // Check for timeout during read
                $info = stream_get_meta_data($socket);
                if ($info['timed_out'] ?? false) {
                    throw (new ClientTimeoutException("Read timeout from $server after {$timeout}s"))
                        ->withServer($server)
                        ->withQuery($query)
                        ->withRawBody($response);
                }
            }
        } finally {
            fclose($socket);
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

        // Truncate at >>> marker (VeriSign/Identity Digital/Afilias boundary)
        if (preg_match('/^>>>.*<<<\s*$/m', $response, $m, \PREG_OFFSET_CAPTURE)) {
            $response = substr($response, 0, $m[0][1]);
        }

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
            if ($trimmed[0] === '%' || $trimmed[0] === '#' || $trimmed[0] === ';') {
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

    /**
     * Open a TCP connection to the WHOIS server.
     *
     * @return resource Stream socket
     */
    private function connect(string $server, int $port, int $timeout): mixed
    {
        $context = stream_context_create();

        // Configure SOCKS proxy if set
        $proxyUri = $this->proxyUri;
        if ($proxyUri !== null) {
            $proxyParts = parse_url($proxyUri);
            if ($proxyParts !== false && isset($proxyParts['host'])) {
                $proxyHost = $proxyParts['host'];
                $proxyPort = $proxyParts['port'] ?? 1080;
                // Use TCP connection through proxy
                stream_context_set_option($context, 'socket', 'tcp_nodelay', true);
                $address = "tcp://$proxyHost:$proxyPort";
            }
        }

        $address ??= "tcp://$server:$port";

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($socket === false) {
            if ($errno === 110 || str_contains(strtolower($errstr), 'timed out')) {
                throw (new ClientTimeoutException("Connection timeout to $server:$port after {$timeout}s"))
                    ->withServer($server);
            }
            throw (new ClientConnectException("Failed to connect to $server:$port: [$errno] $errstr"))
                ->withServer($server);
        }

        // Set stream timeout for reads
        stream_set_timeout($socket, $timeout);

        return $socket;
    }
}
