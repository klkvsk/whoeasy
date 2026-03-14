<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoeasyException;
use RuntimeException;

class ClientException extends RuntimeException implements WhoeasyException
{
}