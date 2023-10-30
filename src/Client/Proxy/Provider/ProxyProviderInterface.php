<?php

namespace Klkvsk\Whoeasy\Client\Proxy\Provider;

use Klkvsk\Whoeasy\Client\Proxy\Proxy;
use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;

interface ProxyProviderInterface
{
    public function getProxy(ServerInfoInterface $server): ?ProxyInterface;

    public function markFailed(ProxyInterface $proxy): void;
}