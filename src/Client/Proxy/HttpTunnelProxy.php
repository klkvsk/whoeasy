<?php

namespace Klkvsk\Whoeasy\Client\Proxy;

use Klkvsk\Whoeasy\Client\Exception\ProxyConnectException;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

class HttpTunnelProxy extends Proxy implements SocketProxyInterface
{
    public function __construct(string $type, string $host, int $port, ?string $username = null, ?string $password = null)
    {
        if ($type !== 'http' && $type !== 'https') {
            throw new InvalidArgumentException("Proxy type '$type' is not supported for HTTP-tunnels");
        }
        if ($type === 'https' && !extension_loaded('openssl')) {
            throw new MissingRequirementsException('OpenSSL extension must be enabled to use a proxy over https');
        }
        parent::__construct($type, $host, $port, $username, $password);
    }

    /**
     * @throws ProxyConnectException
     */
    public function createSocket(string $host, int $port, float $connectTimeout)
    {
        $uri = match ($this->type) {
                'http' => 'tcp',
                'https' => 'ssl'
            }
            . '://' . $this->host . ':' . $this->port;

        $timeStart = microtime(true);

        $socket = @stream_socket_client($uri, $errno, $errorMessage, $connectTimeout);

        if (!is_resource($socket)) {
            throw new ProxyConnectException("Unable to connect to proxy $uri: $errorMessage (code $errno)");
        }

        $timeLeft = $connectTimeout - (microtime(true) - $timeStart);
        stream_set_timeout($socket, floor($timeLeft), fmod($timeLeft, 1) * 1000);

        $request = [];
        $request[] = "CONNECT $host:$port HTTP/1.1";
        $request[] = "Host: $host";
        $request[] = "Proxy-Connection: close";
        if ($this->username || $this->password) {
            $basicAuthToken = base64_encode("$this->username:$this->password");
            $request[] = "Proxy-Authorization: Basic $basicAuthToken";
        }

        $body = implode("\r\n", $request) . "\r\n\r\n";
        $sent = fwrite($socket, $body);

        if ($sent !== strlen($body)) {
            throw new ProxyConnectException(
                'Error while sending data via proxy - sent ' . $sent . ' of ' . strlen($body) . ')'
            );
        }

        $proxyResponse = '';
        $ready = false;
        stream_set_blocking($socket, false);
        do {
            $streams = [ $socket ];
            $write = $except = [];
            if (stream_select($streams, $write, $except, 0, 100_000) === false) {
                break;
            }
            while (($c = fgetc($socket)) !== false) {
                $proxyResponse .= $c;
                if (str_ends_with($proxyResponse, "\n\n") || str_ends_with($proxyResponse, "\r\n\r\n")) {
                    $ready = true;
                }
            }
        } while (!$ready);

        if (!$ready) {
            throw new ProxyConnectException('Socket was closed while waiting for proxy CONNECT response');
        }

        if (!preg_match('#^HTTP/1\.1 (\d{3}) .+$#m', $proxyResponse, $m)) {
            throw new ProxyConnectException(
                'Got malformed response from proxy: "'
                . rtrim(strtok(ltrim($proxyResponse), "\n")) . '"'
            );
        }

        if (intval($m[1]) !== 200) {
            throw new ProxyConnectException(
                'Got non-200 response from proxy: "' . $m[0] . '"'
            );
        }

        return $socket;
    }
}