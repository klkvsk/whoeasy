<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Enum\QueryMode;

readonly class Config
{
    public function __construct(
        public QueryMode $defaultMode = QueryMode::PreferRdap,
        public ?string $proxyUri = null,
        public int $whoisTimeout = 30,
        public int $rdapTimeout = 15,
    ) {}
}
