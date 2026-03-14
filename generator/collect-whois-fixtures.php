<?php

/**
 * WHOIS Fixture Collector
 *
 * Queries WHOIS servers from the TLD registry and saves raw responses as fixtures.
 * Structure: tests/Fixture/Whois/{server-hostname}/{sample-domain}.txt
 * Also queries a random non-existent domain → nxdomain.txt
 * Rate-limited responses → ratelimit.txt, other errors → error.txt
 *
 * Resumable: skips servers where sample domain fixture already exists.
 * Use -f to force re-fetch all.
 *
 * Usage: php generator/collect-whois-fixtures.php [--limit=N] [--delay=MS] [-f]
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use Klkvsk\Whoeasy\Registry\Data\TldServers;

$fixtureDir = __DIR__ . '/../tests/Fixture/Whois';
if (!is_dir($fixtureDir)) {
    mkdir($fixtureDir, 0755, true);
}

// Parse CLI args
$limit = null;
$delay = 1500; // ms between queries
$force = false;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--limit=')) {
        $limit = (int)substr($arg, 8);
    }
    if (str_starts_with($arg, '--delay=')) {
        $delay = (int)substr($arg, 8);
    }
    if ($arg === '-f' || $arg === '--force') {
        $force = true;
    }
}

$client = new WhoisClient(timeout: 10);
$tlds = TldServers::data();
$sampleDomains = require __DIR__ . '/data/sample-domains.php';

// Build unique server → sample domain mapping
$serverSamples = [];
foreach ($tlds as $tld => $info) {
    $whoisServer = $info[0];
    if ($whoisServer === null) continue;
    if (isset($serverSamples[$whoisServer])) continue;

    $cleanTld = ltrim($tld, '.');

    // Use sample domain from generated sample-domains.php if available
    $sample = $sampleDomains[$tld] ?? null;
    if ($sample === null) {
        // Fallback: nic.{tld} for single-level, example.{tld} for multi-level
        if (str_contains($cleanTld, '.')) {
            $sample = "example.$cleanTld";
        } else {
            $sample = "nic.$cleanTld";
        }
    }

    $serverSamples[$whoisServer] = [
        'tld' => $tld,
        'sample' => $sample,
    ];
}

/**
 * Generate a random non-existent domain for a given TLD.
 */
function generateNxdomain(string $tld): string
{
    $cleanTld = ltrim($tld, '.');
    $random = 'xq' . bin2hex(random_bytes(6)) . 'zj';
    return "$random.$cleanTld";
}

/**
 * Sanitize server hostname for use as directory name.
 */
function serverDirName(string $server): string
{
    return str_replace(['/', ':', ' '], ['-', '-', ''], $server);
}

/**
 * Save a response to a file inside the server's directory.
 */
function saveFixture(string $fixtureDir, string $server, string $filename, string $content): void
{
    $dir = $fixtureDir . '/' . serverDirName($server);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents("$dir/$filename", $content);
}

/**
 * Check if a fixture file exists and is non-trivial.
 */
function fixtureExists(string $fixtureDir, string $server, string $filename): bool
{
    $path = $fixtureDir . '/' . serverDirName($server) . '/' . $filename;
    return file_exists($path) && filesize($path) > 10;
}

echo "=== WHOIS Fixture Collector ===\n";
echo "Servers to query: " . count($serverSamples) . "\n";
if ($limit) echo "Limit: $limit\n";
if ($force) echo "Mode: FORCE re-fetch\n";
echo "Delay: {$delay}ms\n";
echo "Fixture dir: $fixtureDir\n\n";

$stats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'rate_limited' => 0, 'timeout' => 0];
$failures = [];

foreach ($serverSamples as $server => $info) {
    if ($limit !== null && $stats['total'] >= $limit) break;

    $stats['total']++;
    $tld = $info['tld'];
    $sample = $info['sample'];
    $sampleFilename = str_replace(['/', ':'], ['-', '-'], $sample) . '.txt';
    $nxdomain = generateNxdomain($tld);

    // Skip if sample domain fixture already exists (unless -f)
    if (!$force && fixtureExists($fixtureDir, $server, $sampleFilename)) {
        $stats['skipped']++;
        continue;
    }

    // --- Query 1: sample domain ---
    echo sprintf("[%d/%d] %s (%s) ... ",
        $stats['total'], count($serverSamples), $server, $sample);

    try {
        $response = $client->query($server, $sample, timeout: 10);

        if (strlen($response) < 10) {
            echo "EMPTY";
            $stats['failed']++;
            $failures[] = "$server: empty response for $sample";
            saveFixture($fixtureDir, $server, 'error.txt', $response);
        } elseif (WhoisClient::isRateLimited($response)) {
            echo "RATE LIMITED";
            $stats['rate_limited']++;
            $failures[] = "$server: rate limited";
            saveFixture($fixtureDir, $server, 'ratelimit.txt', $response);
        } else {
            saveFixture($fixtureDir, $server, $sampleFilename, $response);
            $size = strlen($response);
            echo "OK ({$size} bytes)";
            $stats['success']++;
        }
    } catch (\Klkvsk\Whoeasy\Exception\TimeoutException $e) {
        echo "TIMEOUT";
        $stats['timeout']++;
        $failures[] = "$server: timeout for $sample";
        saveFixture($fixtureDir, $server, 'error.txt', "TIMEOUT: " . $e->getMessage());
    } catch (\Klkvsk\Whoeasy\Exception\ConnectionException $e) {
        echo "CONNECT FAILED";
        $stats['failed']++;
        $failures[] = "$server: " . $e->getMessage();
        saveFixture($fixtureDir, $server, 'error.txt', "CONNECTION: " . $e->getMessage());
    } catch (\Throwable $e) {
        echo "ERROR: " . $e->getMessage();
        $stats['failed']++;
        $failures[] = "$server: " . $e->getMessage();
        saveFixture($fixtureDir, $server, 'error.txt', "ERROR: " . $e->getMessage());
    }

    echo "\n";

    if ($delay > 0) usleep($delay * 1000);

    // --- Query 2: non-existent domain (nxdomain) ---
    if (!$force && fixtureExists($fixtureDir, $server, 'nxdomain.txt')) {
        // Already have nxdomain fixture, skip
    } else {
        echo sprintf("       ↳ nxdomain (%s) ... ", $nxdomain);

        try {
            $nxResponse = $client->query($server, $nxdomain, timeout: 10);

            if (WhoisClient::isRateLimited($nxResponse)) {
                echo "RATE LIMITED\n";
                saveFixture($fixtureDir, $server, 'ratelimit.txt', $nxResponse);
            } else {
                saveFixture($fixtureDir, $server, 'nxdomain.txt', $nxResponse);
                echo "OK (" . strlen($nxResponse) . " bytes)\n";
            }
        } catch (\Throwable $e) {
            echo "ERROR: " . $e->getMessage() . "\n";
            // Non-critical, don't count as failure
        }

        if ($delay > 0) usleep($delay * 1000);
    }
}

echo "\n=== Summary ===\n";
echo "Total:        {$stats['total']}\n";
echo "Success:      {$stats['success']}\n";
echo "Skipped:      {$stats['skipped']} (already had fixtures)\n";
echo "Failed:       {$stats['failed']}\n";
echo "Rate Limited: {$stats['rate_limited']}\n";
echo "Timeout:      {$stats['timeout']}\n";

$existingDirs = count(glob("$fixtureDir/*/", GLOB_ONLYDIR));
echo "\nServer directories on disk: $existingDirs\n";

if ($failures) {
    $logFile = __DIR__ . '/whois-collection.log';
    file_put_contents($logFile, date('Y-m-d H:i:s') . "\n" . implode("\n", $failures) . "\n\n", FILE_APPEND);
    echo "Failures logged to: $logFile\n";
}
