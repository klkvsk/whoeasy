<?php

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoisException;

class CurlRequestException extends ClientRequestException implements WhoisException
{
}