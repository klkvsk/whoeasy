<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
abstract readonly class ProtocolHop
{
    /**
     * @param TInfo|null $info
     */
    public function __construct(
        public string $server,
        public string $query,
        public string $response,
        public ?AbstractInfo $info = null,
        public ?\Throwable $error = null,
    ) {}

    abstract public function toArray(): array;
}
