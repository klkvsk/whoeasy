<?php

namespace Klkvsk\Whoeasy\Client\Proxy;

use Klkvsk\Whoeasy\Exception\InvalidArgumentException;

class Proxy implements ProxyInterface
{
    public function __construct(
        protected string  $type,
        protected string  $host,
        protected int     $port,
        protected ?string $username = null,
        protected ?string $password = null,
    )
    {

    }

    public static function fromUri(string $uri): static
    {
        $parsed = parse_url($uri);

        return new static(
            $parsed['scheme'] ?? throw new InvalidArgumentException('no type'),
            $parsed['host'] ?? throw new InvalidArgumentException('no host'),
            $parsed['port'] ?? throw new InvalidArgumentException('no port'),
            $parsed['user'] ?? null,
            $parsed['pass'] ?? null
        );

    }

    public function getUri(): string
    {
        $uri = $this->type . '://';
        if ($this->username || $this->password) {
            $uri .= "$this->username:$this->password@";
        }
        $uri .= "$this->host:$this->port";
        return $uri;
    }
}