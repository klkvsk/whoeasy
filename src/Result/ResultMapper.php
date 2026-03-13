<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Enum\ContactType;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Data\AsnResult;
use Klkvsk\Whoeasy\Parser\Data\ContactResult;
use Klkvsk\Whoeasy\Parser\Data\DomainResult;
use Klkvsk\Whoeasy\Parser\Data\IpResult;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class ResultMapper
{
    public function mapWhoisAnswer(WhoisAnswer $answer): StructuredResult
    {
        $queryType = self::mapQueryType($answer->queryType);
        $result = $answer->result;

        return new StructuredResult(
            queryType: $queryType,
            domain: $result instanceof DomainResult ? $this->mapDomain($result) : null,
            ip: $result instanceof IpResult ? $this->mapIp($result) : null,
            asn: $result instanceof AsnResult ? $this->mapAsn($result) : null,
        );
    }

    public function mapRawResponse(WhoisAnswer $answer): RawResponse
    {
        return new RawResponse(
            server: $answer->server,
            text: $answer->rawData,
        );
    }

    private static function mapQueryType(string $queryType): QueryType
    {
        return match ($queryType) {
            RequestInterface::QUERY_TYPE_DOMAIN => QueryType::Domain,
            RequestInterface::QUERY_TYPE_IPV4 => QueryType::Ipv4,
            RequestInterface::QUERY_TYPE_IPV6 => QueryType::Ipv6,
            RequestInterface::QUERY_TYPE_ASN => QueryType::Asn,
            default => QueryType::Domain,
        };
    }

    private function mapDomain(DomainResult $d): DomainInfo
    {
        return new DomainInfo(
            name: $d->name,
            registrar: $d->registrar?->name,
            registrarInfo: $d->registrar !== null ? $this->mapRegistrar($d->registrar) : null,
            createdDate: $d->created?->format('Y-m-d H:i:s'),
            updatedDate: $d->changed?->format('Y-m-d H:i:s'),
            expiresDate: $d->expires?->format('Y-m-d H:i:s'),
            status: $d->status ? array_map('trim', explode(',', $d->status)) : [],
            nameservers: $d->nameservers ? array_map(
                fn(string $ns) => new Nameserver(hostname: $ns),
                $d->nameservers,
            ) : [],
            contacts: array_map(
                fn(ContactResult $c) => $this->mapContact($c),
                $d->contacts,
            ),
        );
    }

    private function mapIp(IpResult $ip): IpInfo
    {
        return new IpInfo(
            range: $ip->range,
            networkName: $ip->name,
            country: $ip->owner?->address ? $this->extractCountry($ip->owner->address) : null,
            createdDate: $ip->created?->format('Y-m-d H:i:s'),
            updatedDate: $ip->changed?->format('Y-m-d H:i:s'),
            contacts: array_merge(
                $ip->owner !== null && !$ip->owner->isEmpty()
                    ? [$this->mapContact($ip->owner, 'registrant')]
                    : [],
                array_map(
                    fn(ContactResult $c) => $this->mapContact($c),
                    $ip->contacts,
                ),
            ),
        );
    }

    private function mapAsn(AsnResult $asn): AsnInfo
    {
        $asnNumber = null;
        if ($asn->asn !== null) {
            $asnNumber = (int)preg_replace('/^AS/i', '', $asn->asn);
        }

        return new AsnInfo(
            asn: $asnNumber,
            name: $asn->name,
            createdDate: $asn->created?->format('Y-m-d H:i:s'),
            updatedDate: $asn->changed?->format('Y-m-d H:i:s'),
            contacts: array_merge(
                $asn->owner !== null && !$asn->owner->isEmpty()
                    ? [$this->mapContact($asn->owner, 'registrant')]
                    : [],
                array_map(
                    fn(ContactResult $c) => $this->mapContact($c),
                    $asn->contacts,
                ),
            ),
        );
    }

    private function mapRegistrar(ContactResult $r): Registrar
    {
        return new Registrar(
            name: $r->name,
            url: null,
            abuseEmail: $r->email,
            abusePhone: $r->phone,
        );
    }

    private function mapContact(ContactResult $c, ?string $typeOverride = null): Contact
    {
        $type = $typeOverride ?? $c->type ?? 'registrant';

        return new Contact(
            type: self::mapContactType($type),
            name: $c->name,
            email: $c->email,
            phone: $c->phone,
            address: $c->address,
        );
    }

    private static function mapContactType(string $type): ContactType
    {
        return match (strtolower($type)) {
            'admin', 'administrative' => ContactType::Admin,
            'tech', 'technical' => ContactType::Tech,
            'abuse' => ContactType::Abuse,
            default => ContactType::Registrant,
        };
    }

    private function extractCountry(?string $address): ?string
    {
        if ($address === null) {
            return null;
        }
        $parts = array_map('trim', explode(',', $address));
        foreach ($parts as $part) {
            if (preg_match('/^[A-Z]{2}$/', $part)) {
                return $part;
            }
        }
        return null;
    }
}
