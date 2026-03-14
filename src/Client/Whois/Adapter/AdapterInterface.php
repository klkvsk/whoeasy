<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois\Adapter;

use Klkvsk\Whoeasy\Client\Whois\RequestInterface;
use Klkvsk\Whoeasy\Client\Whois\ResponseInterface;

interface AdapterInterface
{
    public function canHandle(RequestInterface $request): bool;

    public function handle(RequestInterface $request): ResponseInterface;
}
