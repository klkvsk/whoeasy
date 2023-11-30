<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\Request;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ServerInfo;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;

class AdditionalServerRegistry implements ServerRegistryInterface
{
    public function findServer(string $name): ?ServerInfoInterface
    {
        return match($name) {
            'www.dnsbelgium.be' => new ServerInfo(
                'https://api.dnsbelgium.be',
                null,
                [
                    RequestInterface::QUERY_TYPE_DOMAIN => "GET /whois/registration/%s"
                ]
            ),
            'whois.arin.net' => new ServerInfo(
                'whois://whois.arin.net',
                'UTF-8',
                [
                    RequestInterface::QUERY_TYPE_IPV4 => 'n + %s',
                    RequestInterface::QUERY_TYPE_IPV6 => 'n + %s',
                ]
            ),
            default => null,
        };
    }

    public function findByQuery(string $query, string $queryType = null): ?ServerInfoInterface
    {
        $queryType ??= Request::guessQueryType($query);

        return null;
    }

}