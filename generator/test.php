<?php

use Klkvsk\Whoeasy\Whois;

require __DIR__ . '/../vendor/autoload.php';

set_error_handler(fn($s, $m, $f = null, $l = null) => new ErrorException($m, 0, $s, $f, $l), E_ALL);

$response = Whois::getParsed($argv[1], "whois.porkbun.com");

$key = $argv[2] ?? 'rawData';

echo '## server = ' . $response->server . "\n";
echo '## template = ' . $response->novutecResult?->template . "\n";
$value = $response->$key;
if (is_object($value) && method_exists($value, 'toArray')) {
    $value = $value->toArray();
}
echo is_string($value) ? ($value) : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
echo PHP_EOL;

