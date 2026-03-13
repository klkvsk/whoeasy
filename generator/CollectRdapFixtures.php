<?php

/**
 * RDAP Fixture Collector
 *
 * Queries RDAP servers from the TLD registry and saves raw JSON responses as fixtures.
 * Resumable: skips TLDs that already have fixtures.
 *
 * Usage: php generator/CollectRdapFixtures.php [--limit=N] [--delay=MS]
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Klkvsk\Whoeasy\Registry\Data\TldServers;

$fixtureDir = __DIR__ . '/../tests/Fixture/Rdap';
if (!is_dir($fixtureDir)) {
    mkdir($fixtureDir, 0755, true);
}

// Parse CLI args
$limit = null;
$delay = 500; // ms between queries
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--limit=')) {
        $limit = (int)substr($arg, 8);
    }
    if (str_starts_with($arg, '--delay=')) {
        $delay = (int)substr($arg, 8);
    }
}

if (!extension_loaded('curl')) {
    echo "ERROR: curl extension required for RDAP queries\n";
    exit(1);
}

$tlds = TldServers::data();

// Build TLD → RDAP URL mapping with sample domains
$rdapTargets = [];
foreach ($tlds as $tld => $info) {
    $rdapUrl = $info[1];
    if ($rdapUrl === null) continue;

    $cleanTld = ltrim($tld, '.');

    // Skip multi-level TLDs for simplicity
    if (str_contains($cleanTld, '.')) continue;

    // Use well-known domains for popular TLDs, "nic.{tld}" for others
    $sample = match ($cleanTld) {
        'com' => 'google.com',
        'net' => 'cloudflare.net',
        'org' => 'wikipedia.org',
        'info' => 'info.info',
        'biz' => 'nic.biz',
        'edu' => 'mit.edu',
        'uk' => 'google.co.uk',
        'de' => 'google.de',
        'fr' => 'google.fr',
        'au' => 'google.com.au',
        'br' => 'registro.br',
        'ca' => 'google.ca',
        'nl' => 'google.nl',
        'pl' => 'google.pl',
        default => "nic.$cleanTld",
    };

    $rdapTargets[$cleanTld] = [
        'rdap_url' => $rdapUrl,
        'sample' => $sample,
    ];
}

echo "=== RDAP Fixture Collector ===\n";
echo "TLDs with RDAP: " . count($rdapTargets) . "\n";
if ($limit) echo "Limit: $limit\n";
echo "Delay: {$delay}ms\n";
echo "Fixture dir: $fixtureDir\n\n";

$stats = ['total' => 0, 'success' => 0, 'skipped' => 0, 'failed' => 0, 'not_found' => 0];
$failures = [];

foreach ($rdapTargets as $tld => $info) {
    if ($limit !== null && $stats['total'] >= $limit) break;

    $stats['total']++;
    $rdapUrl = $info['rdap_url'];
    $sample = $info['sample'];

    $filename = "$tld.json";
    $filepath = "$fixtureDir/$filename";

    // Skip if fixture already exists and is non-trivial
    if (file_exists($filepath) && filesize($filepath) > 50) {
        $stats['skipped']++;
        continue;
    }

    $url = rtrim($rdapUrl, '/') . '/domain/' . rawurlencode($sample);
    echo sprintf("[%d/%d] %s (%s) ... ", $stats['total'], count($rdapTargets), $tld, $sample);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => ['Accept: application/rdap+json, application/json'],
        CURLOPT_USERAGENT => 'whoeasy/2.0 (RDAP fixture collector)',
    ]);

    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($errno || $error) {
        echo "ERROR: $error\n";
        $stats['failed']++;
        $failures[] = "$tld: $error";
        if ($delay > 0) usleep($delay * 1000);
        continue;
    }

    if ($httpCode === 404) {
        echo "NOT FOUND\n";
        $stats['not_found']++;
        if ($delay > 0) usleep($delay * 1000);
        continue;
    }

    if ($httpCode === 429) {
        echo "RATE LIMITED\n";
        $stats['failed']++;
        $failures[] = "$tld: rate limited";
        // Wait extra on rate limit
        usleep(3000000);
        continue;
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        echo "HTTP $httpCode\n";
        $stats['failed']++;
        $failures[] = "$tld: HTTP $httpCode";
        if ($delay > 0) usleep($delay * 1000);
        continue;
    }

    // Validate it's valid JSON
    $json = json_decode($body, true);
    if (!is_array($json)) {
        echo "INVALID JSON\n";
        $stats['failed']++;
        $failures[] = "$tld: invalid JSON response";
        if ($delay > 0) usleep($delay * 1000);
        continue;
    }

    // Pretty-print for readability
    $prettyJson = json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    file_put_contents($filepath, $prettyJson);
    $size = strlen($prettyJson);
    echo "OK ({$size} bytes)\n";
    $stats['success']++;

    if ($delay > 0) usleep($delay * 1000);
}

echo "\n=== Summary ===\n";
echo "Total:      {$stats['total']}\n";
echo "Success:    {$stats['success']}\n";
echo "Skipped:    {$stats['skipped']} (already had fixtures)\n";
echo "Not Found:  {$stats['not_found']}\n";
echo "Failed:     {$stats['failed']}\n";

$existingFixtures = count(glob("$fixtureDir/*.json"));
echo "\nTotal RDAP fixtures on disk: $existingFixtures\n";

if ($failures) {
    $logFile = __DIR__ . '/rdap-collection.log';
    file_put_contents($logFile, date('Y-m-d H:i:s') . "\n" . implode("\n", $failures) . "\n\n", FILE_APPEND);
    echo "Failures logged to: $logFile\n";
}
