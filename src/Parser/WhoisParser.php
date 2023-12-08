<?php

namespace Klkvsk\Whoeasy\Parser;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Process\DataProcessorInterface;

class WhoisParser
{
    public function __construct(
        /** @var DataProcessorInterface[] $processors */
        protected array $processors,
    )
    {
    }

    public function parse(WhoisAnswer $answer): WhoisAnswer
    {
        foreach ($this->processors as $processor) {
            $processor->process($answer);
        }

        return $answer;
    }
}