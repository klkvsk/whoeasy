<?php

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result;

class Hu extends Standard
{

    public function parse(Result $result, string $rawData): void
    {
        $rawData = utf8_encode($rawData);
        parent::parse($result, $rawData);
    }


    protected function reformatData(): void
    {
        $dateFields = [ 'record created' ];
        foreach ($dateFields as $field) {
            if (array_key_exists($field, $this->data) && strlen($this->data[$field])) {
                $this->data[$field] = str_replace('.', '-', $this->data[$field]);
            }
        }
    }


    public function translateRawData(string $rawData): string
    {
        return utf8_encode($rawData);
    }
}
