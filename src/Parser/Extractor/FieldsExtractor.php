<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

class FieldsExtractor extends Extractor
{
    public readonly array $fields;

    public function __construct(array $fields)
    {
        $this->fields = $fields;
    }

    public function field(string ...$patterns): mixed
    {
        foreach ($patterns as $pattern) {
            foreach ($this->fields as $key => $value) {
                if (self::matchKey($pattern, $key)) {
                    return $value;
                }
            }
        }
        return null;
    }

    public function after(string ...$patterns): ?self
    {
        $skippedKeys = [];
        foreach ($this->fields as $key => $value) {
            foreach ($patterns as $pattern) {
                if (self::matchKey($pattern, $key)) {
                    $nextFields = array_diff_key($this->fields, $skippedKeys);
                    return new self($nextFields);
                }
            }
            $skippedKeys[$key] = true;
        }
        return new FieldsExtractor([]);
    }

    protected function matchKey($pattern, $key): bool
    {
        return fnmatch($pattern, $key, FNM_CASEFOLD | FNM_NOESCAPE);
    }


}