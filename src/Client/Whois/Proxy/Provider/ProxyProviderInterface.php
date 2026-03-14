<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois\Proxy\Provider;

use Klkvsk\Whoeasy\Client\Whois\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\Whois\ServerInfoInterface;

interface ProxyProviderInterface
{
    public function getProxy(ServerInfoInterface $server): ?ProxyInterface;

    public function markFailed(ProxyInterface $proxy): void;
}
