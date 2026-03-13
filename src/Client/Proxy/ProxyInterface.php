<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Proxy;

interface ProxyInterface extends \Stringable
{
    public function getUri(): string;
}