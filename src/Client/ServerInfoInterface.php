<?php

namespace Klkvsk\Whoeasy\Client;

interface ServerInfoInterface
{
    public function getUri(): string;

    public function getName(): string;

    public function getCharset(): ?string;

    public function getQueryFormat(string $queryType);

    public function formatQuery(string $query, string $queryType): string;
}