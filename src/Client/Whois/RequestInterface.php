<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Whois\Proxy\ProxyInterface;

interface RequestInterface
{
    public function getServer(): ServerInfoInterface;

    public function getQuery(): string;

    public function getQueryString(): string;

    public function getQueryType(): string;

    public function getTimeout(): ?float;

    public function getProxy(): ?ProxyInterface;

    public function setProxy(?ProxyInterface $proxy): static;
}
