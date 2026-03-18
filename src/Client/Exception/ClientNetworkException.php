<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\RetryableException;
use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientNetworkException extends ClientRequestException implements WhoeasyException, RetryableException
{
}
