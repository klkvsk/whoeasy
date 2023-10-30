<?php

namespace Klkvsk\Whoeasy\Client\Proxy\Provider;

use Klkvsk\Whoeasy\Client\Proxy\Proxy;
use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;

class ProxyProvider implements ProxyProviderInterface
{
    protected array $proxyList = [];

    public function add(string $proxyUri): static
    {
        $this->proxyList[] = $proxyUri;

        return $this;
    }

    final public function addList(array $proxyUris): static
    {
        foreach ($proxyUris as $proxyUri) {
            $this->add($proxyUri);
        }

        return $this;
    }

    public function getProxy(ServerInfoInterface $server): ?ProxyInterface
    {
        if (empty($this->proxyList)) {
            return null;
        }

        $randomUri = $this->proxyList[rand(0, count($this->proxyList) - 1)];

        return Proxy::fromUri($randomUri);
    }

    public function markFailed(ProxyInterface $proxy): void
    {
        // ignore
    }

}