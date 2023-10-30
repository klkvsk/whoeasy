<?php

namespace Klkvsk\Whoeasy\Client\Exception;

use Klkvsk\Whoeasy\Exception\WhoisException;

class ClientConnectException extends ClientNetworkException implements WhoisException
{
}