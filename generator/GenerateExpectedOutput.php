<?php

/**
 * Expected Output Generator
 *
 * Parses all WHOIS and RDAP fixtures and saves the expected parsed output as JSON.
 * This output is used by parameterized tests to validate parser behavior.
 *
 * Usage: php generator/GenerateExpectedOutput.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Client\Rdap\RdapParser;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;

$whoisFixtureDir = __DIR__ . '/../tests/Fixture/Whois';
$rdapFixtureDir = __DIR__ . '/../tests/Fixture/Rdap';
$expectedDir = __DIR__ . '/../tests/Fixture/Expected';

if (!is_dir($expectedDir)) {
    mkdir($expectedDir, 0755, true);
}

$whoisParser = new WhoisParser();
$rdapParser = new RdapParser();

echo "=== Expected Output Generator ===\n\n";

// --- WHOIS fixtures ---
$whoisFiles = glob("$whoisFixtureDir/*.txt");
$whoisStats = ['total' => 0, 'success' => 0, 'failed' => 0, 'empty' => 0];

echo "Processing " . count($whoisFiles) . " WHOIS fixtures...\n";

foreach ($whoisFiles as $file) {
    $whoisStats['total']++;
    $basename = basename($file, '.txt');
    $raw = file_get_contents($file);

    if (strlen($raw) < 20) {
        $whoisStats['empty']++;
        continue;
    }

    // Determine query type from filename hints
    $queryType = QueryType::Domain;
    if (str_contains($basename, '-ip') || str_contains($basename, 'ripe') || str_contains($basename, 'arin') || str_contains($basename, 'apnic') || str_contains($basename, 'lacnic') || str_contains($basename, 'afrinic')) {
        $queryType = QueryType::Ipv4;
    }

    try {
        $result = $whoisParser->parse($raw, $basename, $queryType);
        $array = $result->toArray();

        // Skip truly empty results (nothing parsed)
        if (count($array) <= 1) { // just queryType
            $whoisStats['empty']++;
            continue;
        }

        $json = json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $outputFile = "$expectedDir/whois.$basename.json";
        file_put_contents($outputFile, $json);
        $whoisStats['success']++;
    } catch (\Throwable $e) {
        $whoisStats['failed']++;
        echo "  FAIL $basename: " . $e->getMessage() . "\n";
    }
}

echo "WHOIS: {$whoisStats['success']} parsed, {$whoisStats['empty']} empty, {$whoisStats['failed']} failed out of {$whoisStats['total']}\n\n";

// --- RDAP fixtures ---
$rdapFiles = glob("$rdapFixtureDir/*.json");
$rdapStats = ['total' => 0, 'success' => 0, 'failed' => 0, 'empty' => 0];

echo "Processing " . count($rdapFiles) . " RDAP fixtures...\n";

foreach ($rdapFiles as $file) {
    $rdapStats['total']++;
    $basename = basename($file, '.json');
    $rawJson = file_get_contents($file);

    $json = json_decode($rawJson, true);
    if (!is_array($json)) {
        $rdapStats['failed']++;
        echo "  FAIL $basename: invalid JSON\n";
        continue;
    }

    try {
        $response = new RdapResponse(
            server: 'https://rdap.fixture',
            url: "https://rdap.fixture/domain/$basename",
            httpCode: 200,
            json: $json,
            rawBody: $rawJson,
        );

        $intermediateResult = $rdapParser->parse($response);

        // Map intermediate result to StructuredResult via ResultMapper
        $mapper = new \Klkvsk\Whoeasy\Result\ResultMapper();

        // Determine query type from filename
        $queryTypeStr = 'domain';
        if (str_starts_with($basename, 'ip-') || str_starts_with($basename, 'ip6-')) {
            $queryTypeStr = 'ipv4';
        } elseif (str_starts_with($basename, 'autnum-') || str_starts_with($basename, 'asn-')) {
            $queryTypeStr = 'asn';
        }

        $result = $mapper->mapRdapResponse($response, $queryTypeStr);
        $array = $result->toArray();

        if (count($array) <= 1) {
            $rdapStats['empty']++;
            continue;
        }

        $outputJson = json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $outputFile = "$expectedDir/rdap.$basename.json";
        file_put_contents($outputFile, $outputJson);
        $rdapStats['success']++;
    } catch (\Throwable $e) {
        $rdapStats['failed']++;
        echo "  FAIL $basename: " . $e->getMessage() . "\n";
    }
}

echo "RDAP: {$rdapStats['success']} parsed, {$rdapStats['empty']} empty, {$rdapStats['failed']} failed out of {$rdapStats['total']}\n\n";

$totalExpected = count(glob("$expectedDir/*.json"));
echo "Total expected output files: $totalExpected\n";
