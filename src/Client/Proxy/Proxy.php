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

        $type = $parsed['scheme'] ?? 'http';

        // downcast to proper proxy implementation class
        $class = match ($type) {
            'http', 'https' => HttpTunnelProxy::class,
            default         => Proxy::class,
        };

        return new $class(
            $type,
            $parsed['host'] ?? throw new InvalidArgumentException('missing host'),
            $parsed['port'] ?? throw new InvalidArgumentException('missing port'),
            $parsed['user'] ?? null,
            $parsed['pass'] ?? null
        );
    }

    public function __toString(): string
    {
        return $this->getUri();
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