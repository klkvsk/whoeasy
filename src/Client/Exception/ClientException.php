<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoisException;
use RuntimeException;

class ClientException extends RuntimeException implements WhoisException
{
}