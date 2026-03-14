<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Client\Whois\Response;
use Klkvsk\Whoeasy\Client\Whois\ResponseInterface;
use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientResponseException extends ClientRequestException implements WhoeasyException
{
    protected ResponseInterface $response;
    protected ?int $httpCode = null;

    public function withResponse(Response $response): static
    {
        $this->response = $response;
        return $this;
    }

    public function getResponse(): Response
    {
        return $this->response;
    }

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
