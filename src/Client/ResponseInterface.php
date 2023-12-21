<?php

namespace Klkvsk\Whoeasy\Client;

interface ResponseInterface
{
    public function getAnswer(): string;
    public function withAnswer(string $answer): static;
}