<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ResponseInterface;

interface AdapterInterface
{
    public function canHandle(RequestInterface $request): bool;

    public function handle(RequestInterface $request): ResponseInterface;
}