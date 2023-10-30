<?php

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoisException;

class ClientTimeoutException extends ClientRequestException implements WhoisException
{
}