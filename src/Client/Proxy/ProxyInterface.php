<?php

namespace Klkvsk\Whoeasy\Client\Proxy;

interface ProxyInterface extends \Stringable
{
    public function getUri(): string;
}