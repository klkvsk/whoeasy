<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;

class RateLimitException extends ClientResponseException implements WhoeasyException, RetryableException
{
}
