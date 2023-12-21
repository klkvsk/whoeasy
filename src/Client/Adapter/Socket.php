<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientNetworkException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\ProxyConnectException;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProviderInterface;
use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\Proxy\SocketProxyInterface;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\Response;
use Klkvsk\Whoeasy\Client\ResponseInterface;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;

class Socket implements AdapterInterface
{
    public function __construct(
        protected ?ProxyProviderInterface $proxyProvider = null
    )
    {
    }

    public function canHandle(RequestInterface $request): bool
    {
        return str_starts_with($request->getServer()->getUri(), 'whois://');
    }

    public function handle(RequestInterface $request): ResponseInterface
    {
        $timeStart = microtime(true);

        if (!$request->getProxy() && $this->proxyProvider) {
            $proxy = $this->proxyProvider?->getProxy($request->getServer());
            $request->setProxy($proxy);
        }

        try {
            $socket = $this->createSocket(
                $request->getServer(),
                $request->getTimeout(),
                $request->getProxy(),
            );
        } catch (ClientRequestException $e) {
            throw $e->withRequest($request);
        }

        $timeLeft = floatval($request->getTimeout()) - (microtime(true) - $timeStart);
        stream_set_timeout($socket, floor($timeLeft), fmod($timeLeft, 1) * 1000);

        $body = $request->getQueryString() . "\r\n";
        $sent = fwrite($socket, $body);

        if ($sent !== strlen($body)) {
            $message = error_get_last()['message'] ?? '';
            throw (new ClientNetworkException('socket write error' . ($message ? ": $message" : '')))
                ->withRequest($request);
        }

        $answer = '';
        stream_set_blocking($socket, false);
        do {
            $streams = [ $socket ];
            $write = $except = [];
            if (@stream_select($streams, $write, $except, 0, 100_000) === false) {
                $message = error_get_last()['message'] ?? '';
                throw (new ClientNetworkException('socket read error' . ($message ? ": $message" : '')))
                    ->withRequest($request);
            }
            $read = @stream_get_contents($socket);
            if ($read === false) {
                $message = error_get_last()['message'] ?? '';
                throw (new ClientNetworkException('socket read error' . ($message ? ": $message" : '')))
                    ->withRequest($request);
            }
            $answer .= $read;
        } while (!feof($socket));

        return new Response($answer);
    }

    protected function createSocket(ServerInfoInterface $server, int $timeout, ProxyInterface $proxy = null)
    {
        $url = parse_url($server->getUri());
        $host = $url['host'];
        $port = $url['port'] ?? 43;

        if ($proxy) {
            if (!$proxy instanceof SocketProxyInterface) {
                throw new ClientException(
                    'Proxy provider for this adapter should only provide socket-capable proxies'
                );
            }
            try {
                return $proxy->createSocket($host, $port, $timeout);
            } catch (ProxyConnectException $e) {
                $this->proxyProvider->markFailed($proxy);
                throw $e;
            }
        }

        $socket = @stream_socket_client(
            "tcp://$host:$port",
            $errCode,
            $errMsg,
            $timeout
        );

        if (!is_resource($socket)) {
            throw new ClientConnectException(
                "Failed to connect to {$server->getUri()}: $errMsg (code $errCode)"
            );
        }

        return $socket;
    }


}