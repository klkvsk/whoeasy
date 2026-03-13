<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

class RateLimitException extends WhoeasyException implements RetryableException
{
}
