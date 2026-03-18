<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;

class NotSupportedException extends \RuntimeException implements WhoeasyException
{
}
