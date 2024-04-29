<?php

namespace Klkvsk\Whoeasy\Client;

class ServerInfo implements ServerInfoInterface
{
    public function __construct(
        protected string    $uri,
        protected array     $formats = [],
        protected ?string   $charset = 'UTF-8',
        protected ?\Closure $answerProcessor = null,
    )
    {
    }

    public function getName(): string
    {
        return parse_url($this->getUri(), PHP_URL_HOST);
    }

    public function getUri(): string
    {
        return $this->uri;
    }

    public function getCharset(): ?string
    {
        return $this->charset;
    }

    public function formatQuery(string $query, string $queryType): string
    {
        $format = $this->getQueryFormat($queryType);
        if (is_string($format)) {
            $format = fn($query) => sprintf($format, $query);
        }
        return $format($query);
    }

    public function getQueryFormat(string $queryType): string|callable
    {
        return $this->formats[$queryType] ?? '%s';
    }

    public function processAnswer(string $data): string
    {
        if ($this->answerProcessor) {
            $processor = $this->answerProcessor;
            $data = $processor($data);
        }

        return $data;
    }

}