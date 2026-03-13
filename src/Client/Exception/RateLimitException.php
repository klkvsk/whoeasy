<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Exception;



use Klkvsk\Whoeasy\Exception\WhoisException;

class RateLimitException extends ClientResponseException implements WhoisException
{

}