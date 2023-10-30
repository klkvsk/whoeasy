<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\ServerInfoInterface;

interface ServerRegistryInterface
{
    public function findServer(string $name): ?ServerInfoInterface;

    public function findByQuery(string $query, string $queryType = null): ?ServerInfoInterface;
}