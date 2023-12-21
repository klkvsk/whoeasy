<?php

namespace Klkvsk\Whoeasy\Client;

class Response implements ResponseInterface
{
    public function __construct(
        protected string $answer,
    )
    {
        // convert newlines
        $this->answer = trim(str_replace("\r", "", $this->answer));
    }

    public function getAnswer(): string
    {
        return $this->answer;
    }

    public function withAnswer(string $answer): static
    {
        $clone = clone $this;
        $clone->answer = $answer;
        return $clone;
    }
}