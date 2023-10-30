<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

interface DataProcessorInterface
{
    public function process(WhoisAnswer $answer): void;
}