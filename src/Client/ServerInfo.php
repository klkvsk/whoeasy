<?php

namespace Klkvsk\Whoeasy\Client;

class ServerInfo implements ServerInfoInterface
{
    public function __construct(
        protected string  $uri,
        protected ?string $charset = null,
        protected array   $formats = [],
    )
    {
    }

    public function getUri(): string
    {
        return $this->uri;
    }

    public function getName(): string
    {
        return parse_url($this->getUri(), PHP_URL_HOST);
    }

    public function getCharset(): ?string
    {
        return $this->charset;
    }

    public function formatQuery(string $query, string $queryType): string
    {
        return sprintf($this->getQueryFormat($queryType), $query);
    }

    public function getQueryFormat(string $queryType): string
    {
        return $this->formats[$queryType] ?? '%s';
    }

}