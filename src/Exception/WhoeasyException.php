<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

class WhoeasyException extends \RuntimeException
{
    public readonly string $server;
    public readonly string $query;
    public readonly string $rawResponse;

    public function __construct(
        string $message,
        string $server = '',
        string $query = '',
        string $rawResponse = '',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        $this->server = $server;
        $this->query = $query;
        $this->rawResponse = $rawResponse;

        parent::__construct($message, $code, $previous);
    }
}
