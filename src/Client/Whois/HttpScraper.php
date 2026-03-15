<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

use Klkvsk\Whoeasy\Client\Exception\NotScrapeableException;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

/**
 * Answer processors for HTTP-based WHOIS scrapers.
 *
 * Each method converts raw HTML/JSON from an HTTP WHOIS endpoint
 * into WHOIS-like plain text.
 */
final class HttpScraper
{
    /**
     * Process HTTP response through the named scraper.
     *
     * @param string $scraperName Scraper identifier (e.g. "ch", "ph", "pa")
     * @param string $data Raw HTTP response body
     * @return string WHOIS-like text
     */
    public static function process(string $scraperName, string $data): string
    {
        return match ($scraperName) {
            'ch' => self::rdapToWhois($data),
            'ph' => self::processPh($data),
            'pa' => self::processPa($data),
            'gr' => self::processGr($data),
            'tt' => self::processTt($data),
            'tj' => self::processTj($data),
            'not-scrapeable' => throw new NotScrapeableException(
                "This TLD requires manual web lookup"
            ),
            default => throw new \InvalidArgumentException("Unknown scraper: $scraperName"),
        };
    }

    /**
     * Convert RDAP JSON response to WHOIS-like text (used for .ch).
     */
    public static function rdapToWhois(string $data): string
    {
        $json = json_decode($data, true);

        $whois = "domain: " . $json['ldhName'] . "\n";
        $whois .= "status: " . implode(', ', $json['status']) . "\n";
        foreach ($json['events'] as $event) {
            $whois .= "{$event['eventAction']} date: " . $event['eventDate'] . "\n";
        }

        foreach ($json['entities'] ?? [] as $entity) {
            foreach ($entity['roles'] as $role) {
                $whois .= "\n";
                $whois .= "$role name: " . ($entity['vcardArray'][1][1][3] ?? '') . "\n";
                $whois .= "$role address: " . implode(', ', array_filter($entity['vcardArray'][1][2][3] ?? [])) . "\n";
                $whois .= "$role URL: " . ($entity['url'] ?? '') . "\n";
            }
        }

        $whois .= "\n";
        foreach ($json['nameservers'] ?? [] as $nameserver) {
            $whois .= "nameserver: " . $nameserver['ldhName'] . "\n";
        }

        return $whois;
    }

    /**
     * Extract WHOIS text from .ph HTML response (content inside <pre> tags).
     */
    public static function processPh(string $data): string
    {
        if (str_contains($data, 'Domain is available.')) {
            return 'Domain is available.';
        }
        return preg_replace('/^.*<pre>(.*)<\/pre>.*$/s', '$1', $data);
    }

    /**
     * Extract WHOIS text from .pa HTML response (key:value from <li> tags).
     */
    public static function processPa(string $data): string
    {
        if (str_contains($data, 'The domain doesn\'t exist')) {
            return 'Domain is available.';
        }

        if (!preg_match_all('@<li>(.+?): (.+)</li>@', $data, $m)) {
            throw new NotScrapeableException("Failed to find data in response");
        }

        $text = '';
        foreach ($m[1] as $i => $key) {
            $value = $m[2][$i];
            $text .= "$key: $value\n";
        }

        return $text;
    }

    /**
     * Extract WHOIS text from .gr HTML response (<pre> with <br> line breaks).
     */
    public static function processGr(string $data): string
    {
        if (str_contains($data, 'does not appear to be registered yet')) {
            return 'Domain is available.';
        }
        $text = preg_replace('@^.*<pre>(.*)</pre>.*$@si', '$1', $data);
        $text = preg_replace('@\r?\n@', '', $text);
        $text = preg_replace('@<br( /)?>@i', "\n", $text);
        return $text;
    }

    /**
     * Extract WHOIS text from .tt HTML response (DOM/XPath table parsing).
     */
    public static function processTt(string $data): string
    {
        if (!extension_loaded('dom')) {
            throw new MissingRequirementsException('DOM extension must be enabled to parse web response');
        }
        $dom = new \DOMDocument();
        @$dom->loadHTML($data);
        $xpath = new \DOMXPath($dom);
        /** @var \DOMNodeList|\DOMNode[] $tableRows */
        $tableRows = $xpath->query('//div[@class="main"]//tr');
        $text = '';
        foreach ($tableRows as $tableRow) {
            $key = $tableRow->firstChild->textContent;
            $value = $tableRow->lastChild->textContent;
            $value = preg_replace('/\(.+?\)/', '', $value);
            if ($key === 'Expiration Date'
                && preg_match('/^(.+?)\s+(?:&nbsp;?)*\s+(.+)$/', $value, $m)
            ) {
                $value = $m[1];
                $text .= "Status: $m[2]\n";
            }
            $text .= "$key: $value\n";
        }
        $text .= "Registrar Name: NIC.TT\n";
        $text .= "Registrar Email: admin@nic.tt\n";
        return $text;
    }

    /**
     * Extract WHOIS text from .tj HTML response (DOM/XPath table parsing).
     */
    public static function processTj(string $data): string
    {
        if (!extension_loaded('dom')) {
            throw new MissingRequirementsException('DOM extension must be enabled to parse web response');
        }
        if (str_contains($data, 'no records found')) {
            return 'Domain not found';
        }
        $dom = new \DOMDocument();
        @$dom->loadHTML($data);
        $xpath = new \DOMXPath($dom);
        /** @var \DOMNodeList|\DOMNode[] $tableRows */
        $tableRows = $xpath->query('//tr');
        $result = [];
        $section = '';
        $last = null;
        foreach ($tableRows as $tableRow) {
            foreach ($tableRow->childNodes as $child) {
                if ($child->nodeType === XML_TEXT_NODE) {
                    $tableRow->removeChild($child);
                }
            }
            $type = $tableRow->firstChild->attributes->getNamedItem('class');
            $fieldName = trim($tableRow->firstChild->textContent);
            $fieldValue = trim($tableRow->childNodes->item(1)->textContent);
            if ($type->textContent === 'section') {
                $section = $fieldName;
                $result[] = '';
                continue;
            }
            if ($type->textContent === 'subfield') {
                array_push($last, $fieldValue);
                continue;
            }

            $key = $section ? "$section $fieldName" : $fieldName;
            $result[$key] ??= [];
            if ($fieldValue && $fieldValue !== html_entity_decode('&nbsp;')) {
                $result[$key][] = $fieldValue;
            }
            $last = &$result[$key];
        }

        $text = "Status: OK\n";
        foreach ($result as $key => $value) {
            if (is_numeric($key) && !$value) {
                $text .= "\n";
                continue;
            }
            $key = preg_replace('/submitted by/', 'registrant', $key);
            $key = preg_replace('/dns-servers for domain.+/', 'Nameservers', $key);
            $key = preg_replace('/:$/', '', $key);
            $key = preg_replace('/registration data /', '', $key);
            $text .= "$key: " . implode(', ', $value) . "\n";
        }
        return $text;
    }
}
