<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientRequestException extends ClientException implements WhoeasyException
{
    protected ?string $server = null;
    protected ?string $query = null;
    protected ?string $rawBody = null;

    public function withServer(string $server): static
    {
        $this->server = $server;
        return $this;
    }

    public function getServer(): ?string
    {
        return $this->server;
    }

    public function withQuery(string $query): static
    {
        $this->query = $query;
        return $this;
    }

    public function getQuery(): ?string
    {
        return $this->query;
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
