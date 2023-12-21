<?php

namespace Klkvsk\Whoeasy\Parser\Data;

use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ResponseInterface;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result as NovutecResult;

class WhoisAnswer
{
    public string $text;
    public array $fields;
    public array $groups;
    public NovutecResult $novutecResult;
    public \stdClass $result;

    public function __construct(
        public readonly string $rawData,
        public readonly string $query,
        public readonly string $queryType,
        public readonly string $server,
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