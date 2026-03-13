<?php

/**
 * Registry Generator for WhoisParser v2 (Whoeasy)
 *
 * Reads:
 *   - generator/tld_serv_list (TLD → WHOIS server mappings)
 *   - generator/new_gtlds_list (new gTLDs with default whois.nic.{tld})
 *   - generator/ip_del_list, ip_del_recovered.h (IPv4 ranges)
 *   - generator/ip6_del_list (IPv6 ranges)
 *   - generator/as_del_list, as32_del_list (ASN ranges)
 *   - data/rdap/dns.json (IANA RDAP bootstrap for domains)
 *   - data/rdap/ipv4.json, ipv6.json, asn.json (IANA RDAP bootstrap for IP/ASN)
 *
 * Produces:
 *   - src/Registry/Data/TldServers.php
 *   - src/Registry/Data/Ipv4Ranges.php
 *   - src/Registry/Data/Ipv6Ranges.php
 *   - src/Registry/Data/AsnRanges.php
 *
 * Usage: php generator/GenerateRegistry.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/functions.php';

use function Klkvsk\Whoeasy\asn2long;
use function Klkvsk\Whoeasy\ip6prefix2long;

$generator = new class {

    private string $generatorDir;
    private string $dataDir;
    private string $outputDir;

    /** @var array<string, array{whois_server: ?string, rdap_url: ?string}> TLD → server info */
    private array $tldServers = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> [ipLong, maskLong, whoisServer, rdapUrl] */
    private array $ipv4Ranges = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> [prefixLong, maskLong, whoisServer, rdapUrl] */
    private array $ipv6Ranges = [];

    /** @var array<int, array{0: int, 1: int, 2: string, 3: ?string}> [start, end, whoisServer, rdapUrl] */
    private array $asnRanges = [];

    /** @var array<string, string> RDAP TLD → URL mapping from IANA bootstrap */
    private array $rdapTldUrls = [];

    /** @var array<string, string> RDAP RIR server → URL mapping */
    private array $rdapIpv4Urls = [];
    private array $rdapIpv6Urls = [];
    private array $rdapAsnUrls = [];

    public function __construct()
    {
        $this->generatorDir = __DIR__;
        $this->dataDir = dirname(__DIR__) . '/data';
        $this->outputDir = dirname(__DIR__) . '/src/Registry/Data';
    }

    public function run(): void
    {
        echo "=== WhoisParser v2 Registry Generator ===\n\n";

        // 1. Load IANA RDAP bootstrap data
        $this->loadRdapBootstrap();

        // 2. Parse TLD server data
        $this->parseNewGtlds();
        $this->parseTldServList();

        // 3. Merge RDAP URLs into TLD data
        $this->mergeRdapUrls();

        // 4. Parse IP/ASN ranges
        $this->parseIpv4Ranges();
        $this->parseIpv6Ranges();
        $this->parseAsnRanges();

        // 5. Generate output files
        $this->generateTldServers();
        $this->generateIpv4Ranges();
        $this->generateIpv6Ranges();
        $this->generateAsnRanges();

        echo "\n=== Generation complete ===\n";
        echo sprintf("  TLDs:       %d (%d with RDAP)\n",
            count($this->tldServers),
            count(array_filter($this->tldServers, fn($s) => $s['rdap_url'] !== null))
        );
        echo sprintf("  IPv4 ranges: %d\n", count($this->ipv4Ranges));
        echo sprintf("  IPv6 ranges: %d\n", count($this->ipv6Ranges));
        echo sprintf("  ASN ranges:  %d\n", count($this->asnRanges));
    }

    private function loadRdapBootstrap(): void
    {
        echo "Loading IANA RDAP bootstrap data...\n";

        // DNS bootstrap
        $dnsFile = $this->dataDir . '/rdap/dns.json';
        if (file_exists($dnsFile)) {
            $dns = json_decode(file_get_contents($dnsFile), true);
            foreach ($dns['services'] ?? [] as $service) {
                [$tlds, $urls] = $service;
                $url = $this->pickHttpsUrl($urls);
                foreach ($tlds as $tld) {
                    $this->rdapTldUrls[strtolower($tld)] = $url;
                }
            }
            echo "  DNS: " . count($this->rdapTldUrls) . " TLDs with RDAP URLs\n";
        }

        // IPv4 bootstrap
        $ipv4File = $this->dataDir . '/rdap/ipv4.json';
        if (file_exists($ipv4File)) {
            $ipv4 = json_decode(file_get_contents($ipv4File), true);
            foreach ($ipv4['services'] ?? [] as $service) {
                [$ranges, $urls] = $service;
                $url = $this->pickHttpsUrl($urls);
                foreach ($ranges as $range) {
                    $this->rdapIpv4Urls[$range] = $url;
                }
            }
            echo "  IPv4: " . count($this->rdapIpv4Urls) . " ranges\n";
        }

        // IPv6 bootstrap
        $ipv6File = $this->dataDir . '/rdap/ipv6.json';
        if (file_exists($ipv6File)) {
            $ipv6 = json_decode(file_get_contents($ipv6File), true);
            foreach ($ipv6['services'] ?? [] as $service) {
                [$ranges, $urls] = $service;
                $url = $this->pickHttpsUrl($urls);
                foreach ($ranges as $range) {
                    $this->rdapIpv6Urls[$range] = $url;
                }
            }
            echo "  IPv6: " . count($this->rdapIpv6Urls) . " ranges\n";
        }

        // ASN bootstrap
        $asnFile = $this->dataDir . '/rdap/asn.json';
        if (file_exists($asnFile)) {
            $asn = json_decode(file_get_contents($asnFile), true);
            foreach ($asn['services'] ?? [] as $service) {
                [$ranges, $urls] = $service;
                $url = $this->pickHttpsUrl($urls);
                foreach ($ranges as $range) {
                    $this->rdapAsnUrls[$range] = $url;
                }
            }
            echo "  ASN: " . count($this->rdapAsnUrls) . " ranges\n";
        }
    }

    private function pickHttpsUrl(array $urls): string
    {
        // Prefer HTTPS URLs
        foreach ($urls as $url) {
            if (str_starts_with($url, 'https://')) {
                return $url;
            }
        }
        return $urls[0];
    }

    private function parseNewGtlds(): void
    {
        $file = $this->generatorDir . '/new_gtlds_list';
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
                $this->tldServers[$tld] = ['whois_server' => $server, 'rdap_url' => null];
                $count++;
            }
        }
        echo "Parsed new_gtlds_list: $count new gTLDs\n";
    }

    private function parseTldServList(): void
    {
        $file = $this->generatorDir . '/tld_serv_list';
        $count = 0;

        foreach ($this->readLines($file) as $line) {
            $cols = preg_split("/\s+/", $line, -1, PREG_SPLIT_NO_EMPTY);
            if (!$cols || !str_starts_with($cols[0], '.')) {
                continue;
            }

            $tld = array_shift($cols);

            // Parse optional type
            $type = null;
            if ($cols && preg_match('/^[A-Z0-9]+$/', $cols[0])) {
                $type = array_shift($cols);
            }

            // Parse server
            $server = null;
            if ($cols && preg_match('/^([a-z][a-z0-9\-.]+|http.+)$/', $cols[0])) {
                $server = array_shift($cols);
            }

            if ($type === 'NONE') {
                $server = null; // No WHOIS available
            } elseif ($type === 'ARPA' || $type === 'IP6') {
                $server = 'whois.arin.net';
            } elseif ($type === 'WEB' && $server && str_starts_with($server, 'http')) {
                $server = null; // Web-only, no WHOIS
            }

            $this->tldServers[$tld] = [
                'whois_server' => $server,
                'rdap_url' => null,
            ];
            $count++;
        }
        echo "Parsed tld_serv_list: $count TLDs\n";
    }

    private function mergeRdapUrls(): void
    {
        $merged = 0;
        $newTlds = 0;
        foreach ($this->rdapTldUrls as $tld => $url) {
            $key = '.' . $tld;
            if (isset($this->tldServers[$key])) {
                $this->tldServers[$key]['rdap_url'] = $url;
                $merged++;
            } else {
                // TLD exists in RDAP but not in WHOIS list - add it
                $this->tldServers[$key] = [
                    'whois_server' => null,
                    'rdap_url' => $url,
                ];
                $newTlds++;
            }
        }
        echo "Merged RDAP URLs: $merged existing, $newTlds new TLDs\n";
    }

    private function parseIpv4Ranges(): void
    {
        // Build WHOIS server → RDAP URL mapping from IANA bootstrap
        $whoisToRdap = $this->buildWhoisToRdapMap($this->rdapIpv4Urls);

        // Parse ip_del_recovered.h
        $recoveredFile = $this->generatorDir . '/ip_del_recovered.h';
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

        // Parse ip_del_list
        $file = $this->generatorDir . '/ip_del_list';
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
        $whoisToRdap = $this->buildWhoisToRdapMap($this->rdapIpv6Urls);

        $file = $this->generatorDir . '/ip6_del_list';
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
        $whoisToRdap = $this->buildWhoisToRdapMap($this->rdapAsnUrls);

        foreach (['as_del_list', 'as32_del_list'] as $filename) {
            $file = $this->generatorDir . '/' . $filename;
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

        // Sort ASN ranges by start
        usort($this->asnRanges, fn($a, $b) => $a[0] <=> $b[0]);

        echo "Parsed ASN ranges: " . count($this->asnRanges) . "\n";
    }

    /**
     * Build a mapping from WHOIS server hostname to RDAP URL
     * by matching known WHOIS hostnames to RIR RDAP endpoints.
     */
    private function buildWhoisToRdapMap(array $rdapRanges): array
    {
        // Map RIR WHOIS servers to their RDAP URLs
        $rirMap = [
            'whois.afrinic.net' => 'https://rdap.afrinic.net/rdap/',
            'whois.apnic.net' => 'https://rdap.apnic.net/',
            'whois.arin.net' => 'https://rdap.arin.net/registry/',
            'whois.ripe.net' => 'https://rdap.db.ripe.net/',
            'whois.lacnic.net' => 'https://rdap.lacnic.net/rdap/',
        ];

        return $rirMap;
    }

    private function generateTldServers(): void
    {
        $file = $this->outputDir . '/TldServers.php';

        // Sort by TLD
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
 * Index 0 = WHOIS server hostname (null if none), Index 1 = RDAP base URL (null if none).
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

    private function fileHeader(): string
    {
        return <<<'PHP'
<?php
// Generated by generator/GenerateRegistry.php -- DO NOT EDIT

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
