<?php

namespace Klkvsk\Whoeasy\Client;

class Response implements ResponseInterface
{
    public function __construct(
        protected string $answer,
    )
    {
    }

    public function getAnswer(): string
    {
        return $this->answer;
    }
}