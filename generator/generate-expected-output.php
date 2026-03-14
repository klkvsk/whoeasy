<?php

/**
 * Expected Output Generator
 *
 * Walks WHOIS and RDAP fixture directories, parses each sample input with the
 * appropriate parser, and saves the result as {basename}.expected.json alongside
 * the input file. Only processes inputs that don't already have an expected file
 * (unless -f is given).
 *
 * Skips: ratelimit.*, error.* files (not parseable responses).
 * Processes: all other .txt (WHOIS) and .json (RDAP) files including nxdomain.
 *
 * Usage: php generator/generate-expected-output.php [-f]
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Client\Rdap\RdapParser;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Result\ResultMapper;

$whoisFixtureDir = __DIR__ . '/../tests/Fixture/Whois';
$rdapFixtureDir = __DIR__ . '/../tests/Fixture/Rdap';

$force = in_array('-f', $argv) || in_array('--force', $argv);

$whoisParser = new WhoisParser();
$rdapParser = new RdapParser();
$resultMapper = new ResultMapper();

echo "=== Expected Output Generator ===\n";
if ($force) echo "Mode: FORCE regenerate\n";
echo "\n";

// --- WHOIS fixtures ---
// Structure: tests/Fixture/Whois/{server-hostname}/{sample}.txt
$whoisStats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'empty' => 0];

$serverDirs = glob("$whoisFixtureDir/*/", GLOB_ONLYDIR);
echo "WHOIS server directories: " . count($serverDirs) . "\n";

foreach ($serverDirs as $serverDir) {
    $serverHostname = basename($serverDir);
    $files = glob("$serverDir/*.txt");

    foreach ($files as $file) {
        $basename = basename($file, '.txt');

        // Skip non-parseable files
        if (in_array($basename, ['ratelimit', 'error'], true)) {
            continue;
        }

        $whoisStats['total']++;

        $expectedFile = "$serverDir/$basename.expected.json";

        // Skip if expected output already exists (unless -f)
        if (!$force && file_exists($expectedFile)) {
            $whoisStats['skipped']++;
            continue;
        }

        $raw = file_get_contents($file);

        if (strlen($raw) < 20) {
            $whoisStats['empty']++;
            continue;
        }

        // Determine query type from server hostname hints
        $queryType = QueryType::Domain;
        $lowerServer = strtolower($serverHostname);
        if (str_contains($lowerServer, 'ripe') || str_contains($lowerServer, 'arin')
            || str_contains($lowerServer, 'apnic') || str_contains($lowerServer, 'lacnic')
            || str_contains($lowerServer, 'afrinic')) {
            $queryType = QueryType::Ipv4;
        }

        try {
            $result = $whoisParser->parse($raw, $serverHostname, $queryType);
            $array = $result->toArray();

            // Skip truly empty results (only queryType field)
            if (count($array) <= 1) {
                $whoisStats['empty']++;
                continue;
            }

            $json = json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            file_put_contents($expectedFile, $json);
            $whoisStats['success']++;
        } catch (\Throwable $e) {
            $whoisStats['failed']++;
            echo "  FAIL whois/$serverHostname/$basename: " . $e->getMessage() . "\n";
        }
    }
}

echo "WHOIS: {$whoisStats['success']} generated, {$whoisStats['skipped']} skipped, "
    . "{$whoisStats['empty']} empty, {$whoisStats['failed']} failed "
    . "out of {$whoisStats['total']}\n\n";

// --- RDAP fixtures ---
// Structure: tests/Fixture/Rdap/{rdap-server}/{sample}.json
$rdapStats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'empty' => 0];

$rdapServerDirs = glob("$rdapFixtureDir/*/", GLOB_ONLYDIR);
echo "RDAP server directories: " . count($rdapServerDirs) . "\n";

foreach ($rdapServerDirs as $serverDir) {
    $serverName = basename($serverDir);
    $files = glob("$serverDir/*.json");

    foreach ($files as $file) {
        $basename = basename($file, '.json');

        // Skip non-parseable files and already-generated expected files
        if (in_array($basename, ['ratelimit', 'error'], true)) {
            continue;
        }
        if (str_ends_with($basename, '.expected')) {
            continue;
        }

        $rdapStats['total']++;

        $expectedFile = "$serverDir/$basename.expected.json";

        // Skip if expected output already exists (unless -f)
        if (!$force && file_exists($expectedFile)) {
            $rdapStats['skipped']++;
            continue;
        }

        $rawJson = file_get_contents($file);
        $json = json_decode($rawJson, true);

        if (!is_array($json)) {
            $rdapStats['failed']++;
            echo "  FAIL rdap/$serverName/$basename: invalid JSON\n";
            continue;
        }

        // Determine query type from filename
        $queryTypeStr = 'domain';
        if (str_starts_with($basename, 'ip-') || str_starts_with($basename, 'ip6-')) {
            $queryTypeStr = 'ipv4';
        } elseif (str_starts_with($basename, 'autnum-') || str_starts_with($basename, 'asn-')) {
            $queryTypeStr = 'asn';
        }

        try {
            // Reconstruct a plausible RDAP URL from server directory name
            $rdapServer = str_replace('_', '/', $serverName);
            $response = new RdapResponse(
                server: "https://$rdapServer",
                url: "https://$rdapServer/domain/$basename",
                httpCode: 200,
                json: $json,
                rawBody: $rawJson,
            );

            $result = $resultMapper->mapRdapResponse($response, $queryTypeStr);
            $array = $result->toArray();

            if (count($array) <= 1) {
                $rdapStats['empty']++;
                continue;
            }

            $outputJson = json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            file_put_contents($expectedFile, $outputJson);
            $rdapStats['success']++;
        } catch (\Throwable $e) {
            $rdapStats['failed']++;
            echo "  FAIL rdap/$serverName/$basename: " . $e->getMessage() . "\n";
        }
    }
}

echo "RDAP: {$rdapStats['success']} generated, {$rdapStats['skipped']} skipped, "
    . "{$rdapStats['empty']} empty, {$rdapStats['failed']} failed "
    . "out of {$rdapStats['total']}\n\n";

$totalWhois = count(glob("$whoisFixtureDir/*/*.expected.json"));
$totalRdap = count(glob("$rdapFixtureDir/*/*.expected.json"));
echo "Total expected output files: " . ($totalWhois + $totalRdap) . " (WHOIS: $totalWhois, RDAP: $totalRdap)\n";
