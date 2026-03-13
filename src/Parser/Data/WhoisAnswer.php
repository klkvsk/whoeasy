<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Data;

class WhoisAnswer
{
    public string $text;

    public function __construct(
        public readonly string $rawData,
        public readonly string $query,
        public readonly string $queryType,
        public readonly string $server,
    ) {
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