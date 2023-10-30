<?php

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Exception\WhoisException;

class ClientRequestException extends ClientException implements WhoisException
{
    protected RequestInterface $request;

    public function withRequest(RequestInterface $request): static
    {
        $this->request = $request;
        return $this;
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }
}