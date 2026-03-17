<?php

/**
 * Registry Generator for WhoisParser v2 (Whoeasy)
 *
 * Reads:
 *   - generator/tld_serv_list (TLD → WHOIS server mappings, from rfc1036/whois)
 *   - generator/new_gtlds_list (new gTLDs with default whois.nic.{tld})
 *   - generator/ip_del_list, ip_del_recovered.h (IPv4 ranges)
 *   - generator/ip6_del_list (IPv6 ranges)
 *   - generator/as_del_list, as32_del_list (ASN ranges)
 *   - data/rdap/dns.json (IANA RDAP bootstrap for domains)
 *   - data/rdap/ipv4.json, ipv6.json, asn.json (IANA RDAP bootstrap for IP/ASN)
 *   - data/whoisserver-world/tlds/*.json (sample domains, WHOIS servers, RDAP servers)
 *
 * Produces:
 *   - src/Registry/Data/TldServers.php
 *   - src/Registry/Data/Ipv4Ranges.php
 *   - src/Registry/Data/Ipv6Ranges.php
 *   - src/Registry/Data/AsnRanges.php
 *
 * Usage: php generator/generate-registry.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/functions.php';

use function Klkvsk\Whoeasy\asn2long;
use function Klkvsk\Whoeasy\ip6prefix2long;

$generator = new class {

    private string $dataDir;
    private string $outputDir;

    /** @var array<string, array{whois_server: ?string, rdap_url: ?string, sample_domain: ?string}> */
    private array $tldServers = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $ipv4Ranges = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $ipv6Ranges = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    private array $asnRanges = [];

    /** @var array<string, string> RDAP TLD → URL from IANA bootstrap */
    private array $rdapTldUrls = [];

    /** @var array<string, string> RDAP TLD → URL from resolve.rs (preferred, includes unofficial) */
    private array $resolveRsUrls = [];

    private array $rdapIpv4Urls = [];
    private array $rdapIpv6Urls = [];
    private array $rdapAsnUrls = [];

    /** @var array<string, array> whoisserver-world data indexed by TLD name (no dot) */
    private array $wswData = [];

    /** @var string[] Cross-reference warnings */
    private array $warnings = [];

    public function __construct()
    {
        $this->dataDir = __DIR__ . '/data';
        $this->outputDir = dirname(__DIR__) . '/src/Registry/Data';
    }

    public function run(): void
    {
        echo "=== WhoisParser v2 Registry Generator ===\n\n";

        // 1. Load all data sources
        $this->loadRdapBootstrap();
        $this->loadResolveRs();
        $this->loadWhoisserverWorld();

        // 2. Parse TLD server data from rfc1036/whois
        $this->parseNewGtlds();
        $this->parseTldServList();

        // 3. Merge RDAP URLs + whoisserver-world data
        $this->mergeRdapUrls();
        $this->mergeWhoisserverWorld();

        // 4. Apply exclusions (disabled TLDs, disabled WHOIS)
        $this->applyExclusions();

        // 4b. Apply WHOIS server overrides (highest priority)
        $this->applyWhoisOverrides();

        // 5. Cross-reference and warn
        $this->crossReference();

        // 6. Parse IP/ASN ranges
        $this->parseIpv4Ranges();
        $this->parseIpv6Ranges();
        $this->parseAsnRanges();

        // 7. Generate output files
        $this->generateTldServers();
        $this->generateSampleDomains();
        $this->generateIpv4Ranges();
        $this->generateIpv6Ranges();
        $this->generateAsnRanges();

        // 8. Summary
        $withSample = count(array_filter($this->tldServers, fn($s) => $s['sample_domain'] !== null));
        $withRdap = count(array_filter($this->tldServers, fn($s) => $s['rdap_url'] !== null));
        $withWhois = count(array_filter($this->tldServers, fn($s) => $s['whois_server'] !== null));

        echo "\n=== Generation complete ===\n";
        echo sprintf("  TLDs:         %d (%d with WHOIS, %d with RDAP, %d with sample domain)\n",
            count($this->tldServers), $withWhois, $withRdap, $withSample
        );
        echo sprintf("  IPv4 ranges:  %d\n", count($this->ipv4Ranges));
        echo sprintf("  IPv6 ranges:  %d\n", count($this->ipv6Ranges));
        echo sprintf("  ASN ranges:   %d\n", count($this->asnRanges));

        if ($this->warnings) {
            echo sprintf("\n=== Warnings (%d) ===\n", count($this->warnings));
            foreach ($this->warnings as $w) {
                echo "  WARNING: $w\n";
            }
        }
    }

    // ========== Data loading ==========

    private function loadRdapBootstrap(): void
    {
        echo "Loading IANA RDAP bootstrap data...\n";

        $bootstrapFiles = [
            'dns' => ['file' => '/rdap/dns.json', 'target' => 'rdapTldUrls'],
            'ipv4' => ['file' => '/rdap/ipv4.json', 'target' => 'rdapIpv4Urls'],
            'ipv6' => ['file' => '/rdap/ipv6.json', 'target' => 'rdapIpv6Urls'],
            'asn' => ['file' => '/rdap/asn.json', 'target' => 'rdapAsnUrls'],
        ];

        foreach ($bootstrapFiles as $name => $config) {
            $file = $this->dataDir . $config['file'];
            if (!file_exists($file)) continue;

            $data = json_decode(file_get_contents($file), true);
            $target = $config['target'];
            foreach ($data['services'] ?? [] as $service) {
                [$keys, $urls] = $service;
                $url = $this->pickHttpsUrl($urls);
                foreach ($keys as $key) {
                    if ($target === 'rdapTldUrls') {
                        $this->{$target}[strtolower($key)] = $url;
                    } else {
                        $this->{$target}[$key] = $url;
                    }
                }
            }
            echo "  $name: " . count($this->{$target}) . " entries\n";
        }
    }

    private function loadResolveRs(): void
    {
        $file = $this->dataDir . '/rdap/resolve.rs.json';
        if (!file_exists($file)) {
            echo "No resolve.rs data (run update-sources.php first)\n";
            return;
        }

        $data = json_decode(file_get_contents($file), true);
        $lookup = $data['lookup'] ?? $data;

        foreach ($lookup as $tld => $url) {
            if (is_string($url) && $url !== '') {
                $this->resolveRsUrls[strtolower($tld)] = $url;
            }
        }
        echo "Loaded resolve.rs: " . count($this->resolveRsUrls) . " TLDs with RDAP URLs\n";
    }

    private function loadWhoisserverWorld(): void
    {
        $tldDir = $this->dataDir . '/whoisserver-world/tlds';
        if (!is_dir($tldDir)) {
            echo "No whoisserver-world data (run update-sources.php first)\n";
            return;
        }

        $files = glob("$tldDir/*.json");
        echo "Loading whoisserver-world data: " . count($files) . " TLD files...\n";

        foreach ($files as $file) {
            $tld = basename($file, '.json');
            $json = json_decode(file_get_contents($file), true);
            if (is_array($json)) {
                $this->wswData[$tld] = $json;
            }
        }
        echo "  Loaded: " . count($this->wswData) . " TLDs\n";
    }

    // ========== TLD parsing ==========

    private function parseNewGtlds(): void
    {
        $file = $this->dataDir . '/whois-src/new_gtlds_list';
        if (!file_exists($file)) {
            echo "Skipping new_gtlds_list (not found)\n";
            return;
        }

        $count = 0;
        foreach ($this->readLines($file) as $line) {
            if (!preg_match('/^([a-z]{3,}|xn--[a-z0-9-]+)$/', $line)) {
                continue;
            }
            $tld = '.' . $line;
            $server = "whois.nic.$line";
            if (!isset($this->tldServers[$tld])) {
                $this->tldServers[$tld] = ['whois_server' => $server, 'rdap_url' => null, 'sample_domain' => null];
                $count++;
            }
        }
        echo "Parsed new_gtlds_list: $count new gTLDs\n";
    }

    private function parseTldServList(): void
    {
        $file = $this->dataDir . '/whois-src/tld_serv_list';
        $count = 0;

        foreach ($this->readLines($file) as $line) {
            $cols = preg_split("/\s+/", $line, -1, PREG_SPLIT_NO_EMPTY);
            if (!$cols || !str_starts_with($cols[0], '.')) {
                continue;
            }

            $tld = array_shift($cols);

            $type = null;
            if ($cols && preg_match('/^[A-Z0-9]+$/', $cols[0])) {
                $type = array_shift($cols);
            }

            $server = null;
            if ($cols && preg_match('/^([a-z][a-z0-9\-.]+|http.+)$/', $cols[0])) {
                $server = array_shift($cols);
            }

            if ($type === 'NONE') {
                $server = null;
            } elseif ($type === 'ARPA' || $type === 'IP6') {
                $server = 'whois.arin.net';
            } elseif ($type === 'WEB' && $server && str_starts_with($server, 'http')) {
                $server = null;
            }

            $this->tldServers[$tld] = [
                'whois_server' => $server,
                'rdap_url' => $this->tldServers[$tld]['rdap_url'] ?? null,
                'sample_domain' => $this->tldServers[$tld]['sample_domain'] ?? null,
            ];
            $count++;
        }
        echo "Parsed tld_serv_list: $count TLDs\n";
    }

    // ========== Merging ==========

    private function mergeRdapUrls(): void
    {
        // First pass: IANA bootstrap (base)
        $ianaMerged = 0;
        $ianaNew = 0;
        foreach ($this->rdapTldUrls as $tld => $url) {
            $key = '.' . $tld;
            if (isset($this->tldServers[$key])) {
                $this->tldServers[$key]['rdap_url'] = $url;
                $ianaMerged++;
            } else {
                $this->tldServers[$key] = [
                    'whois_server' => null,
                    'rdap_url' => $url,
                    'sample_domain' => null,
                ];
                $ianaNew++;
            }
        }
        echo "Merged IANA RDAP: $ianaMerged existing, $ianaNew new TLDs\n";

        // Second pass: resolve.rs (preferred, overwrites IANA, includes unofficial)
        $rsOverwritten = 0;
        $rsNew = 0;
        $rsAdded = 0;
        foreach ($this->resolveRsUrls as $tld => $url) {
            $key = '.' . $tld;
            if (isset($this->tldServers[$key])) {
                $existing = $this->tldServers[$key]['rdap_url'];
                if ($existing === null) {
                    $rsAdded++;
                } elseif ($existing !== $url) {
                    $rsOverwritten++;
                }
                $this->tldServers[$key]['rdap_url'] = $url;
            } else {
                $this->tldServers[$key] = [
                    'whois_server' => null,
                    'rdap_url' => $url,
                    'sample_domain' => null,
                ];
                $rsNew++;
            }
        }
        echo "Merged resolve.rs RDAP: $rsAdded added, $rsOverwritten overwritten, $rsNew new TLDs\n";
    }

    private function mergeWhoisserverWorld(): void
    {
        $samplesAdded = 0;
        $whoisUpdated = 0;
        $rdapUpdated = 0;
        $newTlds = 0;

        foreach ($this->wswData as $tld => $wsw) {
            $key = '.' . $tld;

            // Pick the first sample domain if available
            $sampleDomain = null;
            if (!empty($wsw['sampleDomains'])) {
                // sampleDomains is keyed by TLD, each value is array of domains
                foreach ($wsw['sampleDomains'] as $domains) {
                    if (is_array($domains) && !empty($domains)) {
                        // Pick a well-known domain if available, otherwise first
                        $sampleDomain = $domains[0];
                        break;
                    }
                }
            }

            $wswWhoisServer = null;
            if (!empty($wsw['whoisServer']) && is_array($wsw['whoisServer'])) {
                $wswWhoisServer = $wsw['whoisServer'][0];
            }

            $wswRdapUrl = null;
            if (!empty($wsw['rdapServers']) && is_array($wsw['rdapServers'])) {
                $wswRdapUrl = $wsw['rdapServers'][0];
            }

            if (!isset($this->tldServers[$key])) {
                // New TLD only in whoisserver-world
                $this->tldServers[$key] = [
                    'whois_server' => $wswWhoisServer,
                    'rdap_url' => $wswRdapUrl,
                    'sample_domain' => $sampleDomain,
                ];
                $newTlds++;
                continue;
            }

            // Add sample domain
            if ($sampleDomain !== null && $this->tldServers[$key]['sample_domain'] === null) {
                $this->tldServers[$key]['sample_domain'] = $sampleDomain;
                $samplesAdded++;
            }

            // Fill in missing WHOIS server from whoisserver-world
            if ($this->tldServers[$key]['whois_server'] === null && $wswWhoisServer !== null) {
                $this->tldServers[$key]['whois_server'] = $wswWhoisServer;
                $whoisUpdated++;
            }

            // Fill in missing RDAP URL from whoisserver-world
            if ($this->tldServers[$key]['rdap_url'] === null && $wswRdapUrl !== null) {
                $this->tldServers[$key]['rdap_url'] = $wswRdapUrl;
                $rdapUpdated++;
            }
        }

        echo "Merged whoisserver-world: $samplesAdded samples, $whoisUpdated WHOIS servers, "
            . "$rdapUpdated RDAP URLs, $newTlds new TLDs\n";
    }

    // ========== Exclusions ==========

    private function applyExclusions(): void
    {
        echo "\nApplying exclusions...\n";

        // Remove revoked/retired TLDs
        $disabledTlds = require $this->dataDir . '/disabled-tlds.php';
        $removedCount = 0;
        foreach ($disabledTlds as $tld) {
            if (isset($this->tldServers[$tld])) {
                unset($this->tldServers[$tld]);
                $removedCount++;
            }
        }
        echo "  Removed $removedCount disabled TLDs\n";

        // Null out WHOIS for RDAP providers that no longer support port 43
        $disabledWhoisRdap = require $this->dataDir . '/disabled-whois-rdap.php';
        $disabledCount = 0;
        foreach ($this->tldServers as $tld => &$info) {
            if ($info['whois_server'] !== null
                && $info['rdap_url'] !== null
                && in_array($info['rdap_url'], $disabledWhoisRdap, true)
            ) {
                $info['whois_server'] = null;
                $disabledCount++;
            }
        }
        unset($info);
        echo "  Disabled WHOIS for $disabledCount TLDs (RDAP-only providers)\n";
    }

    private function applyWhoisOverrides(): void
    {
        $overrides = require $this->dataDir . '/tld-whois-overrides.php';
        $count = 0;
        foreach ($overrides as $tld => $server) {
            if (isset($this->tldServers[$tld])) {
                $this->tldServers[$tld]['whois_server'] = $server;
                $count++;
            } else {
                $this->tldServers[$tld] = [
                    'whois_server' => $server,
                    'rdap_url' => null,
                    'sample_domain' => null,
                ];
                $count++;
            }
        }
        echo "  Applied $count WHOIS server overrides\n";
    }

    // ========== Cross-reference ==========

    private function crossReference(): void
    {
        echo "\nCross-referencing data sources...\n";

        $tslTlds = []; // TLDs from tld_serv_list
        foreach ($this->readLines($this->dataDir . '/whois-src/tld_serv_list') as $line) {
            $cols = preg_split("/\s+/", $line, -1, PREG_SPLIT_NO_EMPTY);
            if ($cols && str_starts_with($cols[0], '.')) {
                $tslTlds[] = $cols[0];
            }
        }
        $tslSet = array_flip($tslTlds);

        // TLDs in whoisserver-world but not in tld_serv_list
        $onlyInWsw = [];
        foreach ($this->wswData as $tld => $wsw) {
            $key = '.' . $tld;
            if (!isset($tslSet[$key])) {
                $wswServer = $wsw['whoisServer'][0] ?? 'no server';
                $onlyInWsw[] = "$key ($wswServer)";
            }
        }
        if ($onlyInWsw) {
            $this->warnings[] = count($onlyInWsw) . " TLDs in whoisserver-world but NOT in tld_serv_list: "
                . implode(', ', array_slice($onlyInWsw, 0, 20))
                . (count($onlyInWsw) > 20 ? ' ...' : '');
        }

        // TLDs in tld_serv_list but not in whoisserver-world
        $onlyInTsl = [];
        foreach ($tslTlds as $tld) {
            $cleanTld = ltrim($tld, '.');
            if (!isset($this->wswData[$cleanTld])) {
                $onlyInTsl[] = $tld;
            }
        }
        if ($onlyInTsl) {
            $this->warnings[] = count($onlyInTsl) . " TLDs in tld_serv_list but NOT in whoisserver-world: "
                . implode(', ', array_slice($onlyInTsl, 0, 20))
                . (count($onlyInTsl) > 20 ? ' ...' : '');
        }

        // WHOIS server mismatches
        $mismatches = [];
        foreach ($this->wswData as $tld => $wsw) {
            $key = '.' . $tld;
            if (!isset($this->tldServers[$key])) continue;

            $wswServer = $wsw['whoisServer'][0] ?? null;
            $tslServer = $this->tldServers[$key]['whois_server'];

            if ($wswServer !== null && $tslServer !== null && $wswServer !== $tslServer) {
                $mismatches[] = "$key: tld_serv_list=$tslServer, whoisserver-world=$wswServer";
            }
        }
        if ($mismatches) {
            $this->warnings[] = count($mismatches) . " WHOIS server mismatches between sources: "
                . implode(', ', array_slice($mismatches, 0, 10))
                . (count($mismatches) > 10 ? ' ...' : '');
        }

        // TLDs without sample domains
        $noSample = 0;
        foreach ($this->tldServers as $tld => $info) {
            if ($info['whois_server'] !== null && $info['sample_domain'] === null) {
                $noSample++;
            }
        }
        if ($noSample > 0) {
            $this->warnings[] = "$noSample TLDs have a WHOIS server but no sample domain (will use nic.{tld} fallback)";
        }

        echo "  Cross-reference complete.\n";
    }

    // ========== IP/ASN parsing ==========

    private function parseIpv4Ranges(): void
    {
        $whoisToRdap = $this->buildWhoisToRdapMap();

        $recoveredFile = $this->dataDir . '/whois-src/ip_del_recovered.h';
        if (file_exists($recoveredFile)) {
            foreach ($this->readLines($recoveredFile) as $line) {
                if (!preg_match("/^\{\s*(\d+)U?L?\s*,\s*(\d+)U?L?\s*,\s*\"([a-z0-9.-]+)\"/i", $line, $cols)) {
                    continue;
                }
                $ip = (int)$cols[1];
                $mask = (int)$cols[2];
                $server = $cols[3];
                $rdap = $whoisToRdap[$server] ?? null;
                $this->ipv4Ranges[] = [$ip, $mask, $server, $rdap];
            }
        }

        $file = $this->dataDir . '/whois-src/ip_del_list';
        foreach ($this->readLines($file) as $line) {
            if (!preg_match("/^([0-9.]+)\/([0-9]{1,2})\s+([a-z0-9.-]+)/i", $line, $cols)) {
                continue;
            }
            $ip = $cols[1];
            $maskBits = (int)$cols[2];
            $server = strtolower($cols[3]);

            if ($server === 'unknown') continue;
            if (!str_contains($server, '.')) $server = "whois.$server.net";

            $ipLong = ip2long($ip);
            if ($ipLong === false || $maskBits > 32 || $maskBits < 0) continue;

            $maskLong = 0xFFFFFFFF & (~0 << (32 - $maskBits));
            $rdap = $whoisToRdap[$server] ?? null;
            $this->ipv4Ranges[] = [$ipLong, $maskLong, $server, $rdap];
        }

        echo "Parsed IPv4 ranges: " . count($this->ipv4Ranges) . "\n";
    }

    private function parseIpv6Ranges(): void
    {
        $whoisToRdap = $this->buildWhoisToRdapMap();

        $file = $this->dataDir . '/whois-src/ip6_del_list';
        foreach ($this->readLines($file) as $line) {
            if (!preg_match('/^([a-f0-9]{4}:[a-f0-9]{4})::\/([0-9]{1,2})\s*(\S+)/i', $line, $cols)) {
                continue;
            }
            $ip = $cols[1];
            $maskBits = (int)$cols[2];
            $server = strtolower($cols[3]);

            if ($server === 'unknown' || $server === 'teredo' || $server === '6to4') continue;
            if (!str_contains($server, '.')) $server = "whois.$server.net";

            $ipLong = ip6prefix2long($ip);
            if ($ipLong === false || $maskBits > 32 || $maskBits < 0) continue;

            $maskLong = 0xFFFFFFFF & (~0 << (32 - $maskBits));
            $rdap = $whoisToRdap[$server] ?? null;
            $this->ipv6Ranges[] = [$ipLong, $maskLong, $server, $rdap];
        }

        echo "Parsed IPv6 ranges: " . count($this->ipv6Ranges) . "\n";
    }

    private function parseAsnRanges(): void
    {
        $whoisToRdap = $this->buildWhoisToRdapMap();

        foreach (['as_del_list', 'as32_del_list'] as $filename) {
            $file = $this->dataDir . '/whois-src/' . $filename;
            if (!file_exists($file)) continue;

            foreach ($this->readLines($file) as $line) {
                if (!preg_match('/^([0-9.]+)\s+([0-9.]+)\s+([a-z0-9.-]+)/i', $line, $cols)) {
                    continue;
                }
                $start = asn2long($cols[1]);
                $end = asn2long($cols[2]);
                $server = strtolower($cols[3]);

                if ($server === 'unknown') continue;
                if (!str_contains($server, '.')) $server = "whois.$server.net";

                $rdap = $whoisToRdap[$server] ?? null;
                $this->asnRanges[] = [$start, $end, $server, $rdap];
            }
        }

        usort($this->asnRanges, fn($a, $b) => $a[0] <=> $b[0]);
        echo "Parsed ASN ranges: " . count($this->asnRanges) . "\n";
    }

    private function buildWhoisToRdapMap(): array
    {
        return [
            'whois.afrinic.net' => 'https://rdap.afrinic.net/rdap/',
            'whois.apnic.net' => 'https://rdap.apnic.net/',
            'whois.arin.net' => 'https://rdap.arin.net/registry/',
            'whois.ripe.net' => 'https://rdap.db.ripe.net/',
            'whois.lacnic.net' => 'https://rdap.lacnic.net/rdap/',
        ];
    }

    // ========== Code generation ==========

    private function generateTldServers(): void
    {
        $file = $this->outputDir . '/TldServers.php';
        ksort($this->tldServers);

        $entries = [];
        foreach ($this->tldServers as $tld => $info) {
            $whois = $info['whois_server'] !== null ? var_export($info['whois_server'], true) : 'null';
            $rdap = $info['rdap_url'] !== null ? var_export($info['rdap_url'], true) : 'null';
            $entries[] = "    " . var_export($tld, true) . " => [$whois, $rdap],";
        }

        $content = $this->fileHeader() . <<<'PHP'

namespace Klkvsk\Whoeasy\Registry\Data;

/**
 * TLD → [whois_server, rdap_url] mapping.
 * Index 0 = WHOIS server hostname (null if none).
 * Index 1 = RDAP base URL (null if none).
 */
final class TldServers
{
    /** @return array<string, array{0: ?string, 1: ?string}> */
    public static function data(): array
    {
        return [

PHP;
        $content .= implode("\n", $entries) . "\n";
        $content .= <<<'PHP'
        ];
    }
}

PHP;

        file_put_contents($file, $content);
        echo "Generated: $file\n";
    }

    private function generateSampleDomains(): void
    {
        $file = $this->dataDir . '/sample-domains-generated.php';
        ksort($this->tldServers);

        $entries = [];
        foreach ($this->tldServers as $tld => $info) {
            if ($info['sample_domain'] === null) continue;
            $entries[] = "    " . var_export($tld, true) . " => " . var_export($info['sample_domain'], true) . ",";
        }

        $content = <<<'PHP'
<?php
// Generated by generator/generate-registry.php -- DO NOT EDIT
// TLD → sample domain mapping for fixture collection only.

return [

PHP;
        $content .= implode("\n", $entries) . "\n";
        $content .= <<<'PHP'
];

PHP;

        file_put_contents($file, $content);
        echo "Generated: $file\n";
    }

    private function generateIpv4Ranges(): void
    {
        $file = $this->outputDir . '/Ipv4Ranges.php';

        $entries = [];
        foreach ($this->ipv4Ranges as $range) {
            [$ip, $mask, $server, $rdap] = $range;
            $rdapStr = $rdap !== null ? var_export($rdap, true) : 'null';
            $entries[] = "    [$ip, $mask, '$server', $rdapStr],";
        }

        $content = $this->fileHeader() . <<<'PHP'

namespace Klkvsk\Whoeasy\Registry\Data;

/**
 * IPv4 ranges: [ipLong, maskLong, whoisServer, rdapUrl].
 */
final class Ipv4Ranges
{
    /** @return array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    public static function data(): array
    {
        return [

PHP;
        $content .= implode("\n", $entries) . "\n";
        $content .= <<<'PHP'
        ];
    }
}

PHP;

        file_put_contents($file, $content);
        echo "Generated: $file\n";
    }

    private function generateIpv6Ranges(): void
    {
        $file = $this->outputDir . '/Ipv6Ranges.php';

        $entries = [];
        foreach ($this->ipv6Ranges as $range) {
            [$ip, $mask, $server, $rdap] = $range;
            $rdapStr = $rdap !== null ? var_export($rdap, true) : 'null';
            $entries[] = "    [$ip, $mask, '$server', $rdapStr],";
        }

        $content = $this->fileHeader() . <<<'PHP'

namespace Klkvsk\Whoeasy\Registry\Data;

/**
 * IPv6 ranges: [prefixLong, maskLong, whoisServer, rdapUrl].
 */
final class Ipv6Ranges
{
    /** @return array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    public static function data(): array
    {
        return [

PHP;
        $content .= implode("\n", $entries) . "\n";
        $content .= <<<'PHP'
        ];
    }
}

PHP;

        file_put_contents($file, $content);
        echo "Generated: $file\n";
    }

    private function generateAsnRanges(): void
    {
        $file = $this->outputDir . '/AsnRanges.php';

        $entries = [];
        foreach ($this->asnRanges as $range) {
            [$start, $end, $server, $rdap] = $range;
            $rdapStr = $rdap !== null ? var_export($rdap, true) : 'null';
            $entries[] = "    [$start, $end, '$server', $rdapStr],";
        }

        $content = $this->fileHeader() . <<<'PHP'

namespace Klkvsk\Whoeasy\Registry\Data;

/**
 * ASN ranges: [startAsn, endAsn, whoisServer, rdapUrl]. Sorted by startAsn.
 */
final class AsnRanges
{
    /** @return array<int, array{0: int, 1: int, 2: string, 3: ?string}> */
    public static function data(): array
    {
        return [

PHP;
        $content .= implode("\n", $entries) . "\n";
        $content .= <<<'PHP'
        ];
    }
}

PHP;

        file_put_contents($file, $content);
        echo "Generated: $file\n";
    }

    // ========== Helpers ==========

    private function pickHttpsUrl(array $urls): string
    {
        foreach ($urls as $url) {
            if (str_starts_with($url, 'https://')) {
                return $url;
            }
        }
        return $urls[0];
    }

    private function fileHeader(): string
    {
        return <<<'PHP'
<?php
// Generated by generator/generate-registry.php -- DO NOT EDIT

declare(strict_types=1);

PHP;
    }

    /** @return iterable<string> */
    private function readLines(string $file): iterable
    {
        $data = file_get_contents($file);
        if ($data === false) {
            throw new RuntimeException("Failed to read: $file");
        }
        foreach (explode("\n", $data) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '/*') || str_starts_with($line, '//')) {
                continue;
            }
            yield $line;
        }
    }
};

$generator->run();
