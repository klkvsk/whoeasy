<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\Exception\NotScrapeableException;
use Klkvsk\Whoeasy\Client\Request;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ServerInfo;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;

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
                null,
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois/registration/%s",
                ]
            ),
            'whois.arin.net'    => new ServerInfo(
                'whois://whois.arin.net',
                'UTF-8',
                [
                    RequestInterface::QUERY_TYPE_IPV4 => 'n + %s',
                    RequestInterface::QUERY_TYPE_IPV6 => 'n + %s',
                ]
            ),
            'whois.denic.de'    => new ServerInfo(
                'whois://whois.denic.de',
                'UTF-8',
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => '-T dn %s',
                ]
            ),
            "www.vnnic.vn"      => new ServerInfo(
                // not official, but works without captcha
                "https://whois.net.vn",
                'UTF-8',
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois.php?domain=%s&act=getwhois",
                ]
            ),
            "www.tonic.to" => new ServerInfo(
                "https://www.tonic.to/",
                'UTF-8',
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois?%s",
                ]
            ),
            "whois.nic.ch" => new ServerInfo(
                "https://rdap.nic.ch",
                "UTF-8",
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /domain/%s",
                ],
                answerProcessor: static::rdapToWhois(...),
            ),
            "whois.dot.ph" => new ServerInfo(
                "https://whois.dot.ph/",
                "UTF-8",
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