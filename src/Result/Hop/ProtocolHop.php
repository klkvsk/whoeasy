<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

abstract readonly class ProtocolHop
{
    public ?\Throwable $error;

    abstract public function toArray(): array;
}
