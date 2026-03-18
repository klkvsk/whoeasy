<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientResponseException extends ClientRequestException implements WhoeasyException
{
    protected ?int $httpCode = null;

    public function withHttpCode(int $httpCode): static
    {
        $this->httpCode = $httpCode;
        return $this;
    }

    public function getHttpCode(): ?int
    {
        return $this->httpCode;
    }
}
