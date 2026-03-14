<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Client\Whois\RequestInterface;
use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientRequestException extends ClientException implements WhoeasyException
{
    protected ?string $server = null;
    protected ?string $query = null;
    protected ?RequestInterface $request = null;
    protected ?string $rawBody = null;

    public function withServer(string $server): static
    {
        $this->server = $server;
        return $this;
    }

    public function getServer(): ?string
    {
        return $this->server ?? $this->request?->getServer()->getName();
    }

    public function withQuery(string $query): static
    {
        $this->query = $query;
        return $this;
    }

    public function getQuery(): ?string
    {
        return $this->query ?? $this->request?->getQuery();
    }

    public function withRequest(RequestInterface $request): static
    {
        $this->request = $request;
        return $this;
    }

    public function getRequest(): ?RequestInterface
    {
        return $this->request;
    }

    public function withRawBody(string $rawBody): static
    {
        $this->rawBody = $rawBody;
        return $this;
    }

    public function getRawBody(): ?string
    {
        return $this->rawBody;
    }
}
