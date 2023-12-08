<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

use Klkvsk\Whoeasy\Parser\Exception\ParserException;

abstract class Extractor
{
    abstract public function field(string ...$patterns): mixed;

    public function date(string ...$patterns): ?\DateTimeImmutable
    {
        $value = $this->field(...$patterns);
        if (!$value) {
            return null;
        }
        $value = preg_replace('/[$;#].+$/', '', $value);
        $value = preg_replace('/^before /', '', $value);
        $value = preg_replace('@^(\d{1,2})/(\d{1,2})/(\d{4})@', '$3-$2-$1', $value);
        try {
            try {
                $value = new \DateTimeImmutable($value);
            } catch (\Throwable $e) {
                if (str_contains($e->getMessage(), 'timezone could not be found in the database')) {
                    $value = preg_replace('@[a-z/]+$@i', '', $value);
                    $value = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
                } else if (str_contains($e->getMessage(), 'Double time specification')) {
                    $value = str_replace('.', '-', $value);
                    $value = new \DateTimeImmutable($value);
                } else {
                    throw $e;
                }
            }
        } catch (\Throwable $e) {
            throw new ParserException($e->getMessage() . ', value: ' . $value, 0, $e);
        }

        return $value;
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