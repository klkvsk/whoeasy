<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

interface ResponseInterface
{
    public function getAnswer(): string;
    public function withAnswer(string $answer): static;
}
