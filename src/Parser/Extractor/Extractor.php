<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

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
        try {
            return new \DateTimeImmutable($value);
        } catch (\Throwable $e) {
            if (str_contains($e->getMessage(), 'timezone could not be found in the database')) {
                $value = preg_replace('@[a-z/]+$@i', '', $value);
                $value = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
            } else {
                throw $e;
            }
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

    public function arr(string ...$patterns): ?array
    {
        $value = $this->field(...$patterns);
        if ($value === null) {
            return null;
        }
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        $value = array_map(trim(...), $value);
        sort($value);
        return $value;
    }

    public function lcarr(string ...$patterns): ?array
    {
        $value = $this->arr(...$patterns);
        return $value ? array_map('strtolower', $value) : null;
    }

}