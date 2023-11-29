<?php

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\Request;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ServerInfo;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use function Klkvsk\Whoeasy\asn2long;
use function Klkvsk\Whoeasy\ip6prefix2long;

class ServerRegistry implements ServerRegistryInterface
{
    protected array $servers = [];
    protected array $toplevelRefs = [];
    protected array $ipv4Ranges = [];
    protected array $ipv6Ranges = [];
    protected array $asnRanges = [];

    public function __construct()
    {
    }

    public function findByQuery(string $query, string $queryType = null): ?ServerInfoInterface
    {
        $queryType ??= Request::guessQueryType($query);

        return match ($queryType) {
            RequestInterface::QUERY_TYPE_DOMAIN => $this->findByDomain($query),
            RequestInterface::QUERY_TYPE_IPV4 => $this->findByIpv4($query),
            RequestInterface::QUERY_TYPE_IPV6 => $this->findByIpv6($query),
            RequestInterface::QUERY_TYPE_ASN => $this->findByAsn($query),
            default => throw new InvalidArgumentException($queryType)
        };
    }

    protected function findByDomain(string $query): ?ServerInfoInterface
    {
        $domain = rtrim($query, '.');
        do {
            $tld = ".$domain";
            if (isset($this->toplevelRefs[$tld])) {
                return $this->findServer($this->toplevelRefs[$tld]);
            }
            strtok($domain, '.');
            $domain = strtok('');
        } while ($domain);

        return null;
    }

    public function findServer(string $name): ?ServerInfoInterface
    {
        if (!isset($this->servers[$name])) {
            return null;
        }

        return new ServerInfo(
            $this->servers[$name]['uri'],
            $this->servers[$name]['charset'] ?? null,
            $this->servers[$name]['formats'] ?? [],
            $this->servers[$name]['template'] ?? null,
        );
    }

    protected function findByIpv4(string $query): ?ServerInfoInterface
    {
        $ip = ip2long($query);
        if ($ip === false) {
            throw new InvalidArgumentException("bad ipv4: $query");
        }
        foreach ($this->ipv4Ranges as [ $subnetIp, $subnetMask, $serverName ]) {
            if (($ip & $subnetMask) === $subnetIp) {
                return $this->findServer($serverName);
            }
        }
        return null;
    }

    protected function findByIpv6(string $query): ?ServerInfoInterface
    {
        $ipPrefix = ip6prefix2long($query);
        if ($ipPrefix === false) {
            throw new InvalidArgumentException("bad ipv6: $query");
        }
        foreach ($this->ipv6Ranges as [ $subnetPrefix, $subnetMask, $serverName ]) {
            if (($ipPrefix & $subnetMask) === $subnetPrefix) {
                return $this->findServer($serverName);
            }
        }
        return null;
    }

    protected function findByAsn(string $asn): ?ServerInfoInterface
    {
        $number = asn2long($asn);
        if ($number === false) {
            throw new InvalidArgumentException("bad asn: $asn");
        }

        foreach ($this->asnRanges as [ $start, $end, $server ]) {
            if ($start <= $number && $number <= $end) {
                return $this->findServer($server);
            }
        }

        return null;
    }


}