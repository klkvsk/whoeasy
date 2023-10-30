<?php

namespace Klkvsk\Whoeasy\Client\Proxy;

interface SocketProxyInterface extends ProxyInterface
{
    /** @return ?resource stream */
    public function createSocket(string $host, int $port, float $connectTimeout);
}