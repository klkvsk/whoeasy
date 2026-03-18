<?php

/**
 * WHOIS Fixture Collector
 *
 * Queries WHOIS servers from the TLD registry and saves raw responses as fixtures.
 * Structure: tests/Fixture/Whois/{server-hostname}/{sample-domain}.txt
 * Also queries a random non-existent domain → nxdomain.txt
 * Rate-limited responses → ratelimit.txt, other errors → error.txt
 *
 * By default, only collects WHOIS-only TLDs (no RDAP). Use --all to include all TLDs.
 * Resumable: skips servers where sample domain fixture already exists.
 * Use -f to force re-fetch all.
 *
 * Usage: php generator/collect-whois-fixtures.php [--limit=N] [--delay=MS] [--proxy=URI] [--tld=TLD] [--all] [--filter=TYPE] [-f]
 *
 * --filter=domain   Only collect domain fixtures (default if omitted for TLD mode)
 * --filter=ipv4     Only collect IPv4 fixtures from RIR servers
 * --filter=ipv6     Only collect IPv6 fixtures from RIR servers
 * --filter=asn      Only collect ASN fixtures from RIR servers
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Registry\Data\TldServers;

$fixtureDir = __DIR__ . '/../tests/Fixture/Whois';
if (!is_dir($fixtureDir)) {
    mkdir($fixtureDir, 0755, true);
}

// Parse CLI args
$limit = null;
$delay = 100; // ms between queries
$force = false;
$proxyUri = null;
$filterTld = null;
$filterType = null;
$all = false;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--limit=')) {
        $limit = (int)substr($arg, 8);
    }
    if (str_starts_with($arg, '--delay=')) {
        $delay = (int)substr($arg, 8);
    }
    if (str_starts_with($arg, '--proxy=')) {
        $proxyUri = substr($arg, 8);
    }
    if (str_starts_with($arg, '--tld=')) {
        $filterTld = '.' . ltrim(substr($arg, 6), '.');
    }
    if (str_starts_with($arg, '--filter=')) {
        $filterType = substr($arg, 9);
        if (!in_array($filterType, ['domain', 'ipv4', 'ipv6', 'asn'], true)) {
            fwrite(STDERR, "Invalid --filter value: $filterType (must be domain|ipv4|ipv6|asn)\n");
            exit(1);
        }
    }
    if ($arg === '--all') {
        $all = true;
    }
    if ($arg === '-f' || $arg === '--force') {
        $force = true;
    }
}

$client = new WhoisClient(timeout: 3, proxyUri: $proxyUri);

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

/**
 * Build filename for an IP sample.
 * IPv4: ip-1.2.3.4.txt
 * IPv6: ip6-2001_67c_2e8__.txt (colons replaced with underscores)
 */
function ipFilename(string $ip, string $type): string
{
    if ($type === 'ipv6') {
        return 'ip6-' . str_replace(':', '_', $ip) . '.txt';
    }
    return 'ip-' . $ip . '.txt';
}

/**
 * Build filename for an ASN sample.
 * asn-15169.txt
 */
function asnFilename(int $asn): string
{
    return 'asn-' . $asn . '.txt';
}

// ======================================================================
// Collect IP/ASN fixtures from RIR servers
// ======================================================================
if ($filterType !== null && $filterType !== 'domain') {
    $sampleIps = require __DIR__ . '/data/sample-ip.php';

    // Build targets based on filter type
    $targets = [];
    foreach ($sampleIps as $rir => $info) {
        $server = $info['whois'];
        if ($server === null) continue;

        if ($filterType === 'ipv4' && isset($info['ipv4'])) {
            $targets[] = [
                'server' => $server,
                'query' => $info['ipv4'],
                'filename' => ipFilename($info['ipv4'], 'ipv4'),
                'label' => "IPv4 {$info['ipv4']}",
            ];
        } elseif ($filterType === 'ipv6' && isset($info['ipv6'])) {
            $targets[] = [
                'server' => $server,
                'query' => $info['ipv6'],
                'filename' => ipFilename($info['ipv6'], 'ipv6'),
                'label' => "IPv6 {$info['ipv6']}",
            ];
        } elseif ($filterType === 'asn' && isset($info['asn'])) {
            $asn = $info['asn'];
            $targets[] = [
                'server' => $server,
                'query' => "AS$asn",
                'filename' => asnFilename($asn),
                'label' => "ASN $asn",
            ];
        }
    }

    echo "=== WHOIS Fixture Collector ($filterType) ===\n";
    echo "Targets: " . count($targets) . "\n";
    if ($force) echo "Mode: FORCE re-fetch\n";
    if ($proxyUri) echo "Proxy: $proxyUri\n";
    echo "Delay: {$delay}ms\n";
    echo "Fixture dir: $fixtureDir\n\n";

    $stats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'rate_limited' => 0];
    $failures = [];

    foreach ($targets as $target) {
        if ($limit !== null && $stats['total'] >= $limit) break;

        $stats['total']++;
        $server = $target['server'];
        $query = $target['query'];
        $filename = $target['filename'];
        $label = $target['label'];

        if (!$force && fixtureExists($fixtureDir, $server, $filename)) {
            $stats['skipped']++;
            echo sprintf("[%d/%d] %s (%s) ... SKIPPED\n",
                $stats['total'], count($targets), $server, $label);
            continue;
        }

        echo sprintf("[%d/%d] %s (%s) ... ",
            $stats['total'], count($targets), $server, $label);

        try {
            $response = $client->query($server, $query, timeout: 10);

            if (strlen($response) < 10) {
                echo "EMPTY";
                $stats['failed']++;
                $failures[] = "$server: empty response for $label";
            } elseif (WhoisParser::isRateLimited($response)) {
                echo "RATE LIMITED";
                $stats['rate_limited']++;
                $failures[] = "$server: rate limited";
                saveFixture($fixtureDir, $server, 'ratelimit.txt', $response);
            } else {
                saveFixture($fixtureDir, $server, $filename, $response);
                $size = strlen($response);
                echo "OK ({$size} bytes)";
                $stats['success']++;
            }
        } catch (\Throwable $e) {
            echo "ERROR: " . $e->getMessage();
            $stats['failed']++;
            $failures[] = "$server: " . $e->getMessage();
        }

        echo "\n";
        if ($delay > 0) usleep($delay * 1000);
    }

    echo "\n=== Summary ===\n";
    echo "Total:        {$stats['total']}\n";
    echo "Success:      {$stats['success']}\n";
    echo "Skipped:      {$stats['skipped']} (already had fixtures)\n";
    echo "Failed:       {$stats['failed']}\n";
    echo "Rate Limited: {$stats['rate_limited']}\n";

    if ($failures) {
        $logFile = __DIR__ . '/whois-collection.log';
        file_put_contents($logFile, date('Y-m-d H:i:s') . "\n" . implode("\n", $failures) . "\n\n", FILE_APPEND);
        echo "Failures logged to: $logFile\n";
    }

    exit(0);
}

// ======================================================================
// Collect domain fixtures from TLD servers (original behavior)
// ======================================================================
$tlds = TldServers::data();

if ($filterTld !== null) {
    if (!isset($tlds[$filterTld])) {
        fwrite(STDERR, "TLD not found in registry: $filterTld\n");
        exit(1);
    }
    $tlds = [$filterTld => $tlds[$filterTld]];
}
$sampleDomains = require __DIR__ . '/data/sample-domains.php';

// Build unique server → sample domain mapping
$serverSamples = [];
foreach ($tlds as $tld => $info) {
    $whoisServer = $info[0];
    if ($whoisServer === null) continue;
    // By default, only collect WHOIS-only TLDs (no RDAP fallback)
    $rdapUrl = $info[1] ?? null;
    if (!$all && $filterTld === null && $rdapUrl !== null) continue;
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

echo "=== WHOIS Fixture Collector ===\n";
echo "Scope: " . ($filterTld ? "TLD $filterTld" : ($all ? "all TLDs" : "WHOIS-only TLDs (use --all for all)")) . "\n";
echo "Servers to query: " . count($serverSamples) . "\n";
if ($limit) echo "Limit: $limit\n";
if ($force) echo "Mode: FORCE re-fetch\n";
if ($proxyUri) echo "Proxy: $proxyUri\n";
echo "Delay: {$delay}ms\n";
echo "Fixture dir: $fixtureDir\n\n";

$stats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'rate_limited' => 0, 'not_supported' => 0];
$failures = [];
$notSupportedServers = [];

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
        echo sprintf("[%d/%d] %s (%s) ... SKIPPED\n",
            $stats['total'], count($serverSamples), $server, $sample);
        continue;
    }

    // --- Query 1: sample domain ---
    echo sprintf("[%d/%d] %s (%s) ... ",
        $stats['total'], count($serverSamples), $server, $sample);

    $rateLimited = false;

    try {
        $response = $client->query($server, $sample, timeout: 10);

        if (strlen($response) < 10) {
            echo "EMPTY";
            $stats['failed']++;
            $failures[] = "$server: empty response for $sample";
        } elseif (WhoisParser::isRateLimited($response)) {
            echo "RATE LIMITED";
            $stats['rate_limited']++;
            $rateLimited = true;
            $failures[] = "$server: rate limited";
            saveFixture($fixtureDir, $server, 'ratelimit.txt', $response);
        } elseif (WhoisParser::isNotSupported($response)) {
            echo "NOT SUPPORTED";
            echo "\n---\n" . $response . "\n---\n";
            $stats['not_supported']++;
            $notSupportedServers[] = $server;
        } else {
            saveFixture($fixtureDir, $server, $sampleFilename, $response);
            $size = strlen($response);
            echo "OK ({$size} bytes)";
            $stats['success']++;
        }
    } catch (\Throwable $e) {
        echo "ERROR: " . $e->getMessage();
        $stats['failed']++;
        $failures[] = "$server: " . $e->getMessage();
    }

    echo "\n";

    if ($delay > 0) usleep($delay * 1000);

    // --- Query 2: non-existent domain (nxdomain) ---
    // Skip if rate-limited or not supported
    if ($rateLimited || in_array($server, $notSupportedServers, true)) {
        // skip nxdomain
    } elseif (!$force && fixtureExists($fixtureDir, $server, 'nxdomain.txt')) {
        // Already have nxdomain fixture, skip
    } else {
        echo sprintf("       ↳ nxdomain (%s) ... ", $nxdomain);

        try {
            $nxResponse = $client->query($server, $nxdomain, timeout: 10);

            if (WhoisParser::isRateLimited($nxResponse)) {
                echo "RATE LIMITED\n";
                $stats['rate_limited']++;
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
echo "Total:         {$stats['total']}\n";
echo "Success:       {$stats['success']}\n";
echo "Skipped:       {$stats['skipped']} (already had fixtures)\n";
echo "Not Supported: {$stats['not_supported']}\n";
echo "Failed:        {$stats['failed']}\n";
echo "Rate Limited:  {$stats['rate_limited']}\n";

$existingDirs = count(glob("$fixtureDir/*/", GLOB_ONLYDIR));
echo "\nServer directories on disk: $existingDirs\n";

if ($notSupportedServers) {
    echo "\n=== Not Supported Servers (review for WHOIS disable) ===\n";
    foreach ($notSupportedServers as $ns) {
        echo "  - $ns\n";
    }
}

if ($failures) {
    $logFile = __DIR__ . '/whois-collection.log';
    file_put_contents($logFile, date('Y-m-d H:i:s') . "\n" . implode("\n", $failures) . "\n\n", FILE_APPEND);
    echo "Failures logged to: $logFile\n";
}
