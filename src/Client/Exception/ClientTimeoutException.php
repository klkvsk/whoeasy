<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;

class ClientTimeoutException extends ClientNetworkException implements WhoeasyException
{
}
