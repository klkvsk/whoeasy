<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Whois\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Enum\QueryType;
use function Klkvsk\Whoeasy\asn2long;

class Request implements RequestInterface
{
    const DEFAULT_TIMEOUT = 30.0;

    protected string $queryType;
    protected string $queryString;
    protected ?ProxyInterface $proxy = null;

    public function __construct(
        protected ServerInfoInterface $server,
        protected string              $query,
        ?string                       $queryType = null,
        protected float               $timeout = self::DEFAULT_TIMEOUT,
    )
    {
        $this->queryType = $queryType ?: static::guessQueryType($this->query);
        if ($this->queryType === QueryType::Domain->value) {
            $this->query = rtrim($this->query, '.');
        }
        if ($this->queryType === QueryType::Asn->value) {
            $this->query = 'AS' . asn2long($this->query);
        }
        $this->queryString = $this->server->formatQuery($this->query, $this->queryType);
    }

    public static function guessQueryType(string $query): string
    {
        return QueryType::guess($query)->value;
    }

    public function getServer(): ServerInfoInterface
    {
        return $this->server;
    }

    public function getQuery(): string
    {
        return $this->query;
    }

    public function getQueryString(): string
    {
        return $this->queryString;
    }

    public function getQueryType(): string
    {
        return $this->queryType;
    }

    public function getTimeout(): ?float
    {
        return $this->timeout;
    }

    public function getProxy(): ?ProxyInterface
    {
        return $this->proxy;
    }

    public function setProxy(?ProxyInterface $proxy): static
    {
        $this->proxy = $proxy;

        return $this;
    }

}
