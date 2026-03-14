<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;

class CurlRequestException extends ClientRequestException implements WhoeasyException
{
    public function __construct(
        string            $message = "",
        int               $code = 0,
        ?\Throwable       $previous = null,
        protected ?string $verboseLog = null,
    )
    {
        parent::__construct($message, $code, $previous);
    }

    public function getVerboseLog(): ?string
    {
        return $this->verboseLog;
    }
}