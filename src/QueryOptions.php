<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Enum\QueryMode;

readonly class QueryOptions
{
    public function __construct(
        public ?QueryMode $mode = null,
        public ?string $proxyUri = null,
        public ?int $timeout = null,
    ) {}
}
