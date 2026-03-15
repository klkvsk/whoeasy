<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Registry;

use Klkvsk\Whoeasy\Enum\QueryType;

/**
 * Resolved server information for a query.
 */
readonly class ServerInfo
{
    public function __construct(
        public QueryType $queryType,
        public ?string $whoisServer,
        public ?string $rdapUrl,
        public string $query,
        public ?string $queryFormat = null,
        public ?string $charset = null,
        public ?string $httpUrl = null,
        public ?string $httpQueryFormat = null,
        public ?string $httpScraper = null,
    ) {
    }

    public function hasWhois(): bool
    {
        return $this->whoisServer !== null;
    }

    public function hasRdap(): bool
    {
        return $this->rdapUrl !== null;
    }

    public function hasHttpWhois(): bool
    {
        return $this->httpUrl !== null;
    }
}
