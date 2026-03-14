<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

interface ServerInfoInterface
{
    public function getUri(): string;

    public function getName(): string;

    public function getCharset(): ?string;

    public function getQueryFormat(string $queryType);

    public function formatQuery(string $query, string $queryType): string;
}
