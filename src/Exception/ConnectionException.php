<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

class ConnectionException extends WhoeasyException implements RetryableException
{
}
