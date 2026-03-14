<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois\Proxy;

interface ProxyInterface extends \Stringable
{
    public function getUri(): string;
}
