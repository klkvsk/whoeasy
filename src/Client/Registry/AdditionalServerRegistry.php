<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\Exception\NotScrapeableException;
use Klkvsk\Whoeasy\Client\Request;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ServerInfo;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

class AdditionalServerRegistry implements ServerRegistryInterface
{
    public function findByQuery(string $query, string $queryType = null): ?ServerInfoInterface
    {
        $queryType ??= Request::guessQueryType($query);

        return match (true) {
            $queryType == RequestInterface::QUERY_TYPE_DOMAIN && str_ends_with($query, '.vn')
            => $this->findServer('www.vnnic.vn'),

            default
            => null
        };
    }

    public function findServer(string $name): ?ServerInfoInterface
    {
        return match ($name) {
            'www.dnsbelgium.be' => new ServerInfo(
                'https://api.dnsbelgium.be',
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois/registration/%s",
                ]
            ),
            'whois.arin.net'    => new ServerInfo(
                'whois://whois.arin.net',
                [
                    RequestInterface::QUERY_TYPE_IPV4 => 'n + %s',
                    RequestInterface::QUERY_TYPE_IPV6 => 'n + %s',
                ]
            ),
            'whois.denic.de'    => new ServerInfo(
                'whois://whois.denic.de',
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => '-T dn %s',
                ]
            ),
            "www.vnnic.vn"      => new ServerInfo(
                // not official, but works without captcha
                "https://whois.net.vn",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois.php?domain=%s&act=getwhois",
                ]
            ),
            "www.tonic.to" => new ServerInfo(
                "https://www.tonic.to/",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois?%s",
                ]
            ),
            "whois.nic.ch" => new ServerInfo(
                "https://rdap.nic.ch",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /domain/%s",
                ],
                answerProcessor: static::rdapToWhois(...),
            ),
            "whois.dot.ph" => new ServerInfo(
                "https://whois.dot.ph/",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /?search=%s",
                ],
                answerProcessor: function ($data) {
                    if (str_contains($data, 'Domain is available.')) {
                        return 'Domain is available.';
                    }
                    return preg_replace('/^.*<pre>(.*)<\/pre>.*$/s', '$1', $data);
                },
            ),

            "www.nic.pa" => new ServerInfo(
                "http://www.nic.pa/",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /en/whois/dominio/%s",
                ],
                answerProcessor: function ($data) {
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
                },
            ),

            // remap to web version without captcha
            "grweb.ics.forth.gr" => $this->findServer('www.innoview.gr'),

            "www.innoview.gr" => new ServerInfo(
                "https://www.innoview.gr",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "POST /members/whoisdomain.php whoisdomainname=%s",
                ],
                answerProcessor: function ($data) {
                    if (str_contains($data, 'does not appear to be registered yet')) {
                        return 'Domain is available.';
                    }
                    $text = preg_replace('@^.*<pre>(.*)</pre>.*$@si', '$1', $data);
                    $text = preg_replace('@\r?\n@', '', $text);
                    $text = preg_replace('@<br( /)?>@i', "\n", $text);
                    return $text;
                },
            ),


            // remap to web version, as port 43 times out
            "whois.tonic.to" => $this->findServer('www.tonic.to'),
            "www.dominios.es" => new ServerInfo(
                'https://nic.es',
                formats: [
                    RequestInterface::QUERY_TYPE_DOMAIN => "NONE only-web",
                ],
                answerProcessor: function ($data) {
                    throw new NotScrapeableException("use https://nic.es/sgnd/dominio/publicDetalleDominio.action");
                },
            ),
            "www.nic.tt" => new ServerInfo(
                'https://www.nic.tt',
                formats: [
                    RequestInterface::QUERY_TYPE_DOMAIN => "POST /cgi-bin/search.pl name=%s",
                ],
                answerProcessor: function ($data) {
                    if (!extension_loaded('dom')) {
                        throw new MissingRequirementsException('DOM extension must be enabled to parse web response');
                    }
                    $dom = new \DOMDocument();
                    @$dom->loadHTML($data);
                    $xpath = new \DOMXPath($dom);
                    /** @noinspection PhpComposerExtensionStubsInspection */
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
                },
            ),

            "whois.jprs.jp" => new ServerInfo(
                "whois://whois.jprs.jp",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "%s/e",
                ],
            ),

            // those are subordinates of apnic, and apnic itself returns better structured result
            "whois.nic.ad.jp" => new ServerInfo("whois://whois.apnic.net"),
            "whois.twnic.net" => new ServerInfo("whois://whois.apnic.net"),
            "whois.nic.or.kr" => new ServerInfo("whois://whois.apnic.net"),

            default => null,
        };
    }

    protected static function rdapToWhois(string $data): string
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
                $whois .= "$role URL: " . $entity['url'] . "\n";
            }
        }

        $whois .= "\n";
        foreach ($json['nameservers'] ?? [] as $nameserver) {
            $whois .= "nameserver: " . $nameserver['ldhName'] . "\n";
        }

        return $whois;
    }
}