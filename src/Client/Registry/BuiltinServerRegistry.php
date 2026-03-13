<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Registry;

class BuiltinServerRegistry extends CombinedServerRegistry
{
    public function __construct()
    {
        parent::__construct(
            new AdditionalServerRegistry(),
            new GeneratedServerRegistry($this),
        );
    }

}