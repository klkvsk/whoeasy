<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

class TimeoutException extends WhoeasyException implements RetryableException
{
}
