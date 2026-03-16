<?php

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/** @internal */
class ParserResult
{
    public function __construct(
        public AbstractInfo $info,
        public ?string $referralServer = null
    )
    {}
}