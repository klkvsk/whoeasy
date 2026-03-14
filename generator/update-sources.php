<?php

declare(strict_types=1);

set_error_handler(fn($s, $m, $f = null, $l = null) => throw new ErrorException($m, 0, $s, $f, $l), E_ALL);

new class {
    private string $dataDir;

    public function __construct()
    {
        $this->dataDir = __DIR__ . '/data';

        // rfc1036/whois data files (TLD servers, IP/ASN ranges)
        $rfc1036Files = [
            'new_gtlds_list',
            'tld_serv_list',
            'servers_charset_list',
            'nic_handles_list',
            'ip_del_list',
            'ip_del_recovered.h',
            'ip6_del_list',
            'as_del_list',
        ];

        foreach ($rfc1036Files as $file) {
            $url = "https://raw.githubusercontent.com/rfc1036/whois/master/$file";
            echo "Updating whois-src/$file... ";
            $this->fetch($url, $this->dataDir . '/whois-src/' . $file);
        }

        // IANA RDAP bootstrap data
        $rdapDir = $this->dataDir . '/rdap';
        if (!is_dir($rdapDir)) {
            mkdir($rdapDir, 0755, true);
        }

        $rdapFiles = [
            'dns.json' => 'https://data.iana.org/rdap/dns.json',
            'ipv4.json' => 'https://data.iana.org/rdap/ipv4.json',
            'ipv6.json' => 'https://data.iana.org/rdap/ipv6.json',
            'asn.json' => 'https://data.iana.org/rdap/asn.json',
        ];

        foreach ($rdapFiles as $name => $url) {
            echo "Updating rdap/$name... ";
            $this->fetch($url, "$rdapDir/$name");
        }

        // resolve.rs RDAP list (includes unofficial RDAP servers missing from IANA)
        $rdapDir = $this->dataDir . '/rdap';
        echo "Updating rdap/resolve.rs.json... ";
        $this->fetch(
            'https://resolve.rs/domains/rdap.json',
            "$rdapDir/resolve.rs.json"
        );

        // whoisserver-world (7c/whoisserver-world - TLD data with sample domains)
        $this->fetchWhoisserverWorld();

        echo "\nDone. Run generate-registry.php to rebuild.\n";
    }

    private function fetchWhoisserverWorld(): void
    {
        $wswDir = $this->dataDir . '/whoisserver-world';
        if (!is_dir($wswDir)) {
            mkdir($wswDir, 0755, true);
        }

        $zipUrl = 'https://github.com/7c/whoisserver-world/archive/refs/heads/master.zip';
        $zipFile = sys_get_temp_dir() . '/whoisserver-world.zip';

        echo "Fetching whoisserver-world repo zip... ";
        try {
            $content = @file_get_contents($zipUrl);
        } catch (\Throwable) {
            $content = false;
        }
        if ($content === false) {
            echo "FAILED\n";
            return;
        }
        file_put_contents($zipFile, $content);
        echo "OK (" . strlen($content) . " bytes)\n";

        // Extract tlds/*.json from the zip using shell unzip
        $tldDir = "$wswDir/tlds";
        if (!is_dir($tldDir)) {
            mkdir($tldDir, 0755, true);
        }

        $tmpExtract = sys_get_temp_dir() . '/wsw-extract-' . getmypid();
        @mkdir($tmpExtract, 0755, true);

        $escapedZip = escapeshellarg($zipFile);
        $escapedTmp = escapeshellarg($tmpExtract);
        exec("unzip -q -o $escapedZip '*/tlds/*.json' -d $escapedTmp 2>&1", $output, $exitCode);

        if ($exitCode !== 0) {
            echo "Failed to unzip: " . implode("\n", $output) . "\n";
            unlink($zipFile);
            return;
        }

        // Move extracted tld files to target dir
        $extractedTlds = glob("$tmpExtract/*/tlds/*.json");
        $extracted = 0;
        foreach ($extractedTlds as $file) {
            $basename = basename($file);
            rename($file, "$tldDir/$basename");
            $extracted++;
        }

        // Cleanup
        exec("rm -rf $escapedTmp");
        unlink($zipFile);
        echo "Extracted $extracted TLD files to data/whoisserver-world/tlds/\n";
    }

    private function fetch(string $url, string $saveTo): void
    {
        try {
            $content = @file_get_contents($url);
        } catch (\Throwable) {
            $content = false;
        }
        if ($content === false || $content === '') {
            echo "FAILED (may be removed upstream)\n";
            return;
        }

        if (file_exists($saveTo)) {
            $oldContent = file_get_contents($saveTo);
            if ($oldContent === $content) {
                echo "not changed\n";
                return;
            }
            echo "updated\n";
        } else {
            echo "created\n";
        }

        file_put_contents($saveTo, $content);
    }
};
