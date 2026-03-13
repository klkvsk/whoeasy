<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Exception;

use RuntimeException;

class MissingRequirementsException extends RuntimeException implements WhoisException
{

}