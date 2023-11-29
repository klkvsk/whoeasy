<?php

namespace Klkvsk\Whoeasy\Client;

use function Klkvsk\Whoeasy\asn2long;

class Request implements RequestInterface
{
    const DEFAULT_TIMEOUT = 30.0;

    protected string $queryType;
    protected string $queryString;

    public function __construct(
        protected ServerInfoInterface $server,
        protected string              $query,
        string                        $queryType = null,
        protected float               $timeout = self::DEFAULT_TIMEOUT,
    )
    {
        $this->queryType = $queryType ?: static::guessQueryType($this->query);
        if ($this->queryType === self::QUERY_TYPE_DOMAIN) {
            $this->query = rtrim($this->query, '.');
        }
        if ($this->queryType === self::QUERY_TYPE_ASN) {
            $this->query = 'AS' . asn2long($this->query);
        }
        $this->queryString = $this->server->formatQuery($this->query, $this->queryType);
    }

    public static function guessQueryType(string $query): string
    {
        if (preg_match('/-[a-z]$/i', $query)) {
            return self::QUERY_TYPE_NIC_HANDLE;
        }
        if (preg_match('/^asn?[0-9]+$/i', $query)) {
            return self::QUERY_TYPE_ASN;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::QUERY_TYPE_IPV4;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::QUERY_TYPE_IPV6;
        }

        return self::QUERY_TYPE_DOMAIN;
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
}