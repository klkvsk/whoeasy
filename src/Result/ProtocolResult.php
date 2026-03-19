<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Result\Hop\ProtocolHop;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 * @template-covariant THop of ProtocolHop
 */
readonly class ProtocolResult
{
    /**
     * @param TInfo|null $info
     * @param THop[] $hops
     */
    public function __construct(
        public ?AbstractInfo $info = null,
        public array $hops = [],
    ) {}

    public function toArray(): array
    {
        return [
            'info' => $this->info?->toArray(),
            'hops' => array_map(
                fn(ProtocolHop $hop) => $hop->toArray(),
                $this->hops,
            )
        ];
    }
}
