<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\ServerInfoInterface;

class CombinedServerRegistry implements ServerRegistryInterface
{
    protected array $registries;

    public function __construct(
        ServerRegistryInterface ...$registries
    )
    {
        $this->registries = $registries;
    }

    public function add(ServerRegistryInterface $registry): self
    {
        $this->registries[] = $registry;

        return $this;
    }

    public function findByQuery(string $query, string $queryType = null): ?ServerInfoInterface
    {
        foreach ($this->registries as $registry) {
            $server = $registry->findByQuery($query, $queryType);
            if ($server) {
                return $server;
            }
        }
        return null;
    }

    public function findServer(string $name): ?ServerInfoInterface
    {
        foreach ($this->registries as $registry) {
            $server = $registry->findServer($name);
            if ($server) {
                return $server;
            }
        }
        return null;
    }

}