<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Registry;

use Klkvsk\Whoeasy\Client\Whois\ServerInfo;
use Klkvsk\Whoeasy\Client\Whois\ServerInfoInterface;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use function Klkvsk\Whoeasy\asn2long;
use function Klkvsk\Whoeasy\ip6prefix2long;

class GeneratedServerRegistry implements ServerRegistryInterface
{
    use GeneratedServerRegistryData;

    protected ServerRegistryInterface $recursiveRegistry;

    public function __construct(?ServerRegistryInterface $rootRegistry = null)
    {
        // in case with CombinedServerRegistry we need to start lookup from the beginning
        $this->recursiveRegistry = $rootRegistry ?: $this;

        $this->applyFixes();
    }

    private function applyFixes(): void
    {
        if (isset($this->servers['whois.kg'])) {
            $this->servers['whois.kg']['charset'] = 'UTF-8';
        }
    }

    public function findByQuery(string $query, ?string $queryType = null): ?ServerInfoInterface
    {
        $queryType ??= QueryType::guess($query)->value;

        return match ($queryType) {
            QueryType::Domain->value => $this->findByDomain($query),
            QueryType::Ipv4->value   => $this->findByIpv4($query),
            QueryType::Ipv6->value   => $this->findByIpv6($query),
            QueryType::Asn->value    => $this->findByAsn($query),
            default                             => throw new InvalidArgumentException($queryType)
        };
    }

    protected function findByDomain(string $query): ?ServerInfoInterface
    {
        $domain = rtrim($query, '.');
        do {
            $tld = ".$domain";
            if (isset($this->toplevelRefs[$tld])) {
                return $this->recursiveRegistry->findServer($this->toplevelRefs[$tld]);
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
            formats: $this->servers[$name]['formats'] ?? [],
            charset: $this->servers[$name]['charset'] ?? 'UTF-8',
        );
    }

    protected function findByIpv4(string $query): ?ServerInfoInterface
    {
        $ip = ip2long($query);
        if ($ip === false) {
            throw new InvalidArgumentException("bad ipv4: $query");
        }
        foreach ($this->ipv4Ranges as [$subnetIp, $subnetMask, $serverName]) {
            if (($ip & $subnetMask) === $subnetIp) {
                return $this->recursiveRegistry->findServer($serverName);
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
        foreach ($this->ipv6Ranges as [$subnetPrefix, $subnetMask, $serverName]) {
            if (($ipPrefix & $subnetMask) === $subnetPrefix) {
                return $this->recursiveRegistry->findServer($serverName);
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

        foreach ($this->asnRanges as [$start, $end, $server]) {
            if ($start <= $number && $number <= $end) {
                return $this->recursiveRegistry->findServer($server);
            }
        }

        return null;
    }


}