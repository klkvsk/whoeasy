<?php

use Klkvsk\Whoeasy\Whois;

require __DIR__ . '/../vendor/autoload.php';

/** @throws ErrorException */
function exception_error_handler($severity, $message, $file = null, $line = null)
{
    throw new ErrorException($message, 0, $severity, $file, $line);
}

set_error_handler("exception_error_handler", E_ALL);


$response = Whois::getParsed($argv[1]);

$key = $argv[2] ?? 'rawData';
$value = $response->$key;
echo is_string($value) ? $value : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
echo PHP_EOL;

