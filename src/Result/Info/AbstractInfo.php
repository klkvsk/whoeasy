<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Info;

abstract readonly class AbstractInfo
{
    abstract public function toArray(): array;
}
