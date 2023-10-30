<?php

namespace Klkvsk\Whoeasy\Parser;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Process\CleanComments;
use Klkvsk\Whoeasy\Parser\Process\DataProcessorInterface;
use Klkvsk\Whoeasy\Parser\Process\FormatDates;
use Klkvsk\Whoeasy\Parser\Process\GroupedFields;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates;
use Klkvsk\Whoeasy\Parser\Process\SimpleFields;

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