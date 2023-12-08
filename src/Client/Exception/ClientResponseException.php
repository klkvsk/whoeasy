<?php

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Client\Response;
use Klkvsk\Whoeasy\Client\ResponseInterface;
use Klkvsk\Whoeasy\Exception\WhoisException;

class ClientResponseException extends ClientRequestException implements WhoisException
{
    protected ResponseInterface $response;

    public function withResponse(Response $response): static
    {
        $this->response = $response;
        return $this;
    }

    public function getResponse(): Response
    {
        return $this->response;
    }
}