<?php

/**
 * RDAP Fixture Collector
 *
 * Queries RDAP servers from the TLD registry and saves raw JSON responses as fixtures.
 * Structure: tests/Fixture/Rdap/{rdap-server}/{domain}.json
 * Also queries a random non-existent domain → nxdomain.json
 * Rate-limited responses (HTTP 429) → ratelimit.json, other errors → error.json
 *
 * RDAP server directory name: host + path with / replaced by _
 *   e.g. "https://rdap.nic.xyz/v1/" → "rdap.nic.xyz_v1"
 *
 * Resumable: skips servers where sample domain fixture exists.
 * Use -f to force re-fetch all.
 *
 * Usage: php generator/collect-rdap-fixtures.php [--limit=N] [--delay=MS] [--proxy=URI] [--tld=TLD] [-f]
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Registry\Data\TldServers;

$fixtureDir = __DIR__ . '/../tests/Fixture/Rdap';
if (!is_dir($fixtureDir)) {
    mkdir($fixtureDir, 0755, true);
}

// Parse CLI args
$limit = null;
$delay = 500; // ms between queries
$force = false;
$proxyUri = null;
$filterTld = null;
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
    if ($arg === '-f' || $arg === '--force') {
        $force = true;
    }
}

$client = new RdapClient(timeout: 15, proxyUri: $proxyUri);
$tlds = TldServers::data();

if ($filterTld !== null) {
    if (!isset($tlds[$filterTld])) {
        fwrite(STDERR, "TLD not found in registry: $filterTld\n");
        exit(1);
    }
    $tlds = [$filterTld => $tlds[$filterTld]];
}
$sampleDomains = require __DIR__ . '/data/sample-domains.php';

/**
 * Convert RDAP base URL to a directory name.
 * e.g. "https://rdap.nic.xyz/v1/" → "rdap.nic.xyz_v1"
 */
function rdapDirName(string $rdapUrl): string
{
    $parsed = parse_url($rdapUrl);
    $host = $parsed['host'] ?? 'unknown';
    $path = trim($parsed['path'] ?? '', '/');
    if ($path !== '') {
        $path = str_replace('/', '_', $path);
        return "$host" . "_$path";
    }
    return $host;
}

/**
 * Save a fixture file inside the RDAP server's directory.
 */
function saveRdapFixture(string $fixtureDir, string $rdapUrl, string $filename, string $content): void
{
    $dir = $fixtureDir . '/' . rdapDirName($rdapUrl);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents("$dir/$filename", $content);
}

/**
 * Check if a fixture file exists and is non-trivial.
 */
function rdapFixtureExists(string $fixtureDir, string $rdapUrl, string $filename): bool
{
    $path = $fixtureDir . '/' . rdapDirName($rdapUrl) . '/' . $filename;
    return file_exists($path) && filesize($path) > 10;
}

/**
 * Pretty-print JSON body, or return a fallback error JSON.
 */
function prettyJson(?string $body, array $fallback = []): string
{
    if ($body !== null && $body !== '') {
        $json = json_decode($body, true);
        if (is_array($json)) {
            return json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        return $body;
    }
    return json_encode($fallback, JSON_PRETTY_PRINT);
}

/**
 * Generate a random non-existent domain for a given TLD.
 */
function generateNxdomain(string $tld): string
{
    $random = 'xq' . bin2hex(random_bytes(6)) . 'zj';
    return "$random.$tld";
}

/**
 * Query an RDAP URL using RdapClient and save the appropriate fixture.
 *
 * @return string|null 'success'|'not_found'|'rate_limited'|'failed'|null
 */
function queryAndSave(
    RdapClient $client,
    string $fixtureDir,
    string $rdapUrl,
    string $url,
    string $filename,
): ?string {
    try {
        $response = $client->queryUrl($url);
        $pretty = json_encode($response->json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        saveRdapFixture($fixtureDir, $rdapUrl, $filename, $pretty);
        echo "OK (" . strlen($pretty) . " bytes)\n";
        return 'success';
    } catch (RateLimitException $e) {
        echo "RATE LIMITED\n";
        saveRdapFixture($fixtureDir, $rdapUrl, 'ratelimit.json', prettyJson($e->getRawBody()));
        usleep(3000000); // extra wait
        return 'rate_limited';
    } catch (NotFoundException $e) {
        echo "NOT FOUND\n";
        saveRdapFixture($fixtureDir, $rdapUrl, 'nxdomain.json',
            prettyJson($e->getRawBody(), ['errorCode' => 404, 'title' => 'Not Found']));
        return 'not_found';
    } catch (ClientResponseException $e) {
        $code = $e->getHttpCode();
        echo "HTTP $code\n";
        saveRdapFixture($fixtureDir, $rdapUrl, 'error.json',
            prettyJson($e->getRawBody(), ['errorCode' => $code]));
        return 'failed';
    } catch (ClientException $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        saveRdapFixture($fixtureDir, $rdapUrl, 'error.json', json_encode([
            'error' => $e->getMessage(),
            'url' => $url,
        ], JSON_PRETTY_PRINT));
        return 'failed';
    }
}

// Build TLD → RDAP URL mapping with sample domains
$rdapTargets = [];
foreach ($tlds as $tld => $info) {
    $rdapUrl = $info[1];
    if ($rdapUrl === null) continue;

    $cleanTld = ltrim($tld, '.');

    // Skip multi-level TLDs for simplicity
    if (str_contains($cleanTld, '.')) continue;

    // Use sample domain from generated sample-domains.php if available
    $sample = $sampleDomains[$tld] ?? "nic.$cleanTld";

    // Group by RDAP base URL (multiple TLDs may share a server)
    if (!isset($rdapTargets[$rdapUrl])) {
        $rdapTargets[$rdapUrl] = [
            'tld' => $cleanTld,
            'sample' => $sample,
        ];
    }
}

echo "=== RDAP Fixture Collector ===\n";
echo "Unique RDAP servers: " . count($rdapTargets) . "\n";
if ($limit) echo "Limit: $limit\n";
if ($filterTld) echo "TLD filter: $filterTld\n";
if ($force) echo "Mode: FORCE re-fetch\n";
if ($proxyUri) echo "Proxy: $proxyUri\n";
echo "Delay: {$delay}ms\n";
echo "Fixture dir: $fixtureDir\n\n";

$stats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'not_found' => 0, 'rate_limited' => 0];
$failures = [];

foreach ($rdapTargets as $rdapUrl => $info) {
    if ($limit !== null && $stats['total'] >= $limit) break;

    $stats['total']++;
    $tld = $info['tld'];
    $sample = $info['sample'];
    $sampleFilename = str_replace(['/', ':'], ['-', '-'], $sample) . '.json';

    // Skip if sample fixture already exists (unless -f)
    if (!$force && rdapFixtureExists($fixtureDir, $rdapUrl, $sampleFilename)) {
        $stats['skipped']++;
        echo sprintf("[%d/%d] %s (%s) ... SKIPPED\n",
            $stats['total'], count($rdapTargets), rdapDirName($rdapUrl), $sample);
        continue;
    }

    // --- Query 1: sample domain ---
    $url = rtrim($rdapUrl, '/') . '/domain/' . rawurlencode($sample);
    echo sprintf("[%d/%d] %s (%s) ... ", $stats['total'], count($rdapTargets), rdapDirName($rdapUrl), $sample);

    $result = queryAndSave($client, $fixtureDir, $rdapUrl, $url, $sampleFilename);

    if ($result === 'failed' || $result === 'rate_limited') {
        $failures[] = rdapDirName($rdapUrl) . ": $result";
    }
    if ($result !== null) {
        $stats[$result]++;
    }

    if ($delay > 0) usleep($delay * 1000);

    // --- Query 2: non-existent domain (nxdomain) ---
    // Skip if rate-limited — nxdomain query would almost certainly be rate-limited too
    if ($result === 'rate_limited') {
        // skip nxdomain
    } elseif (!$force && rdapFixtureExists($fixtureDir, $rdapUrl, 'nxdomain.json')) {
        // Already have nxdomain, skip
    } elseif ($result !== 'not_found') {
        // If query 1 got 404, it was already saved as nxdomain.json — skip
        $nxdomain = generateNxdomain($tld);
        $nxUrl = rtrim($rdapUrl, '/') . '/domain/' . rawurlencode($nxdomain);
        echo sprintf("       ↳ nxdomain (%s) ... ", $nxdomain);

        try {
            $response = $client->queryUrl($nxUrl);
            // Some servers return 200 with error body for nxdomain
            $pretty = json_encode($response->json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            saveRdapFixture($fixtureDir, $rdapUrl, 'nxdomain.json', $pretty);
            echo "OK (" . strlen($pretty) . " bytes)\n";
        } catch (NotFoundException $e) {
            $content = prettyJson($e->getRawBody(), ['errorCode' => 404, 'title' => 'Not Found']);
            saveRdapFixture($fixtureDir, $rdapUrl, 'nxdomain.json', $content);
            echo "OK (" . strlen($content) . " bytes)\n";
        } catch (RateLimitException $e) {
            echo "RATE LIMITED\n";
            saveRdapFixture($fixtureDir, $rdapUrl, 'ratelimit.json', prettyJson($e->getRawBody()));
            usleep(3000000);
        } catch (ClientException $e) {
            echo "ERROR: " . $e->getMessage() . "\n";
        }

        if ($delay > 0) usleep($delay * 1000);
    }
}

echo "\n=== Summary ===\n";
echo "Total:        {$stats['total']}\n";
echo "Success:      {$stats['success']}\n";
echo "Skipped:      {$stats['skipped']} (already had fixtures)\n";
echo "Not Found:    {$stats['not_found']}\n";
echo "Rate Limited: {$stats['rate_limited']}\n";
echo "Failed:       {$stats['failed']}\n";

$existingDirs = count(glob("$fixtureDir/*/", GLOB_ONLYDIR));
echo "\nServer directories on disk: $existingDirs\n";

if ($failures) {
    $logFile = __DIR__ . '/rdap-collection.log';
    file_put_contents($logFile, date('Y-m-d H:i:s') . "\n" . implode("\n", $failures) . "\n\n", FILE_APPEND);
    echo "Failures logged to: $logFile\n";
}
