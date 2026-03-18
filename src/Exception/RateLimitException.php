<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

class RateLimitException extends \RuntimeException implements WhoeasyException, RetryableException
{
}
