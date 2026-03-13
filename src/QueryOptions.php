<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Enum\AuthLevel;
use Klkvsk\Whoeasy\Enum\QueryMode;

readonly class QueryOptions
{
    public function __construct(
        public ?QueryMode $mode = null,
        public AuthLevel $authLevel = AuthLevel::Auth,
        public ?string $proxyUri = null,
        public ?int $timeout = null,
    ) {}
}
