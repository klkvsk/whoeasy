<?php

namespace Klkvsk\Whoeasy\Client;

class Response implements ResponseInterface
{
    public function __construct(
        protected string $answer,
    )
    {
        // convert newlines
        $this->answer = str_replace("\r", "", $this->answer);
    }

    public function getAnswer(): string
    {
        return $this->answer;
    }
}