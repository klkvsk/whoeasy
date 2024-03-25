<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

use Klkvsk\Whoeasy\Parser\Exception\ParserException;

abstract class Extractor
{
    abstract public function field(string ...$patterns): mixed;

    public static function parseDate(string $value): ?\DateTimeInterface
    {
        $value = preg_replace('/[$;#(].+$/', '', $value);
        $value = preg_replace('/^before /i', '', $value);
        $value = preg_replace('@^(\d{1,2})/(\d{1,2})/(\d{4})@', '$3-$2-$1', $value);
        if (preg_match_all('/[0-9]/', $value) < 4) {
            // less than 4 digits are present, it's not a date for sure
            return null;
        }
        if (empty($value)) {
            return null;
        }
        try {
            try {
                $value = new \DateTimeImmutable($value);
            } catch (\Throwable $e) {
                if (str_contains($e->getMessage(), 'Double time specification')) {
                    $value = str_replace('.', '-', $value);
                    $value = new \DateTimeImmutable($value);
                } elseif (preg_match('/^(\d{4})\. (\d{2})\. (\d{2})\./', $value, $m)) {
                    // .co.kr - 2020. 01. 01.
                    $value = str_replace($m[0], $m[1] . '-' . $m[2] . '-' . $m[3], $value);
                    $value = new \DateTimeImmutable($value);
                } elseif (preg_match('/(20\d{2})(0\d|11|12)([0123]\d)/', $value, $m)) {
                    // improve until 2099
                    $value = $m[1] . '-' . $m[2] . '-' . $m[3];
                    $value = new \DateTimeImmutable($value);
                } elseif (str_contains($e->getMessage(), 'timezone could not be found in the database')) {
                    $value = preg_replace('@[a-z/]+$@i', '', $value);
                    if (empty($value)) {
                        return null;
                    }
                    $value = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
                } else {
                    throw $e;
                }
            }
        } catch (\Throwable $e) {
            throw new ParserException($e->getMessage() . ', value: "' . $value . '"', 0, $e);
        }

        return $value;
    }

    public function date(string ...$patterns): ?\DateTimeInterface
    {
        $value = $this->field(...$patterns);
        if (!$value) {
            return null;
        }
        if (is_array($value)) {
            // most likely it is a "changed" field having multiple values
            // so we take the last one, but it is not guaranteed to be the correct way
            $value = array_pop($value);
        }

        return static::parseDate($value);
    }

    public function string(string ...$patterns): ?string
    {
        $value = $this->field(...$patterns);
        if (is_array($value)) {
            $value = array_unique($value);
            $value = implode(', ', $value);
        }
        $value = trim((string)$value);
        return $value ?: null;
    }

    public function lcstring(string ...$patterns): ?string
    {
        $value = $this->string(...$patterns);
        return $value ? strtolower($value) : null;
    }

    public function arr(string ...$patterns): array
    {
        $value = $this->field(...$patterns);
        if ($value === null) {
            return [];
        }
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        $value = array_map(trim(...), $value);
        sort($value);
        return $value;
    }

    public function lcarr(string ...$patterns): array
    {
        $value = $this->arr(...$patterns);
        return $value ? array_map('strtolower', $value) : [];
    }

}