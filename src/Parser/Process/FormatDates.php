<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use DateTime;
use DateTimeZone;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;
use Throwable;

class FormatDates implements DataProcessorInterface
{
    public function __construct(
        protected string $dateFormat = 'Y-m-d H:i:s e',
        protected bool   $strict = false,
    )
    {
    }

    public function process(WhoisAnswer $answer): void
    {
        $walker = function (&$val) {
            if (is_string($val)) {
                $val = $this->processValue($val);
            }
        };

        if (isset($answer->fields)) {
            array_walk_recursive($answer->fields, $walker);
        }
        if (isset($answer->groups)) {
            array_walk_recursive($answer->groups, $walker);
        }
    }

    public function processValue(string $value): string
    {
        if (!preg_match('/^\d{1,4}-(\d{1,2}|[a-z]{3})-\d{1,4}[-T ]+\d{1,2}:\d{2}([:.]\d{2})?/i', $value, $m)) {
            if ($this->strict) {
                throw new ParserException("Date parsing failed on: " . var_export($value, true));
            } else {
                return $value;
            }
        }

        $onlyDateTime = $m[1];

        try {
            try {
                $dt = new DateTime($value);
            } catch (\Throwable $e) {
                if (str_contains($e->getMessage(), 'timezone could not be found in the database')) {
                    $dt = new DateTime($onlyDateTime);
                } else {
                    throw $e;
                }
            }
        } catch (Throwable $e) {
            if ($this->strict) {
                throw new ParserException("Date parsing failed on: " . var_export($value, true), 0, $e);
            } else {
                return $value;
            }
        }

        $dt->setTimezone(new DateTimeZone('UTC'));
        return $dt->format($this->dateFormat);
    }

}