<?php

namespace Klkvsk\Whoeasy\Parser\Data;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result as NovutecResult;

class WhoisAnswer
{
    public string $text;
    public array $fields;
    public array $groups;
    public NovutecResult $novutecResult;
    public \stdClass $result;

    public function __construct(
        public readonly string  $rawData,
        public readonly ?string $server = null,
        public readonly ?string $query = null,
        public readonly ?string $queryType = null,
    )
    {
        $this->text = $this->rawData;
    }

    public function lines(): iterable
    {
        $offset = 0;
        do {
            $pos = strpos($this->text, "\n", $offset);
            if ($pos !== false) {
                $length = ($pos + 1) - $offset;
                yield substr($this->text, $offset, $length);
                $offset += $length;
            } else {
                yield substr($this->text, $offset);
            }
        } while ($pos !== false);
    }

}