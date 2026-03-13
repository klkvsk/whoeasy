<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Enum\ContactType;

/**
 * Merges two StructuredResult objects from WHOIS and RDAP into one.
 *
 * Strategy: RDAP is the primary source (more structured/standardized),
 * WHOIS fills in gaps. For arrays (contacts, nameservers, status),
 * we deduplicate and combine.
 */
class ResultMerger
{
    /**
     * Merge two structured results. RDAP takes priority for scalar fields,
     * arrays are combined with deduplication.
     */
    public function merge(StructuredResult $rdap, StructuredResult $whois): StructuredResult
    {
        return new StructuredResult(
            queryType: $rdap->queryType,
            domain: $this->mergeDomain($rdap->domain, $whois->domain),
            ip: $this->mergeIp($rdap->ip, $whois->ip),
            asn: $this->mergeAsn($rdap->asn, $whois->asn),
        );
    }

    private function mergeDomain(?DomainInfo $rdap, ?DomainInfo $whois): ?DomainInfo
    {
        if ($rdap === null) {
            return $whois;
        }
        if ($whois === null) {
            return $rdap;
        }

        return new DomainInfo(
            name: $rdap->name ?? $whois->name,
            registrar: $rdap->registrar ?? $whois->registrar,
            registrarInfo: $this->mergeRegistrar($rdap->registrarInfo, $whois->registrarInfo),
            createdDate: $rdap->createdDate ?? $whois->createdDate,
            updatedDate: $rdap->updatedDate ?? $whois->updatedDate,
            expiresDate: $rdap->expiresDate ?? $whois->expiresDate,
            status: $this->mergeStringArrays($rdap->status, $whois->status),
            nameservers: $this->mergeNameservers($rdap->nameservers, $whois->nameservers),
            contacts: $this->mergeContacts($rdap->contacts, $whois->contacts),
            dnssec: $rdap->dnssec ?? $whois->dnssec,
        );
    }

    private function mergeIp(?IpInfo $rdap, ?IpInfo $whois): ?IpInfo
    {
        if ($rdap === null) {
            return $whois;
        }
        if ($whois === null) {
            return $rdap;
        }

        return new IpInfo(
            range: $rdap->range ?? $whois->range,
            networkName: $rdap->networkName ?? $whois->networkName,
            description: $rdap->description ?? $whois->description,
            country: $rdap->country ?? $whois->country,
            createdDate: $rdap->createdDate ?? $whois->createdDate,
            updatedDate: $rdap->updatedDate ?? $whois->updatedDate,
            status: $this->mergeStringArrays($rdap->status, $whois->status),
            contacts: $this->mergeContacts($rdap->contacts, $whois->contacts),
        );
    }

    private function mergeAsn(?AsnInfo $rdap, ?AsnInfo $whois): ?AsnInfo
    {
        if ($rdap === null) {
            return $whois;
        }
        if ($whois === null) {
            return $rdap;
        }

        return new AsnInfo(
            asn: $rdap->asn ?? $whois->asn,
            name: $rdap->name ?? $whois->name,
            description: $rdap->description ?? $whois->description,
            country: $rdap->country ?? $whois->country,
            createdDate: $rdap->createdDate ?? $whois->createdDate,
            updatedDate: $rdap->updatedDate ?? $whois->updatedDate,
            status: $this->mergeStringArrays($rdap->status, $whois->status),
            contacts: $this->mergeContacts($rdap->contacts, $whois->contacts),
        );
    }

    private function mergeRegistrar(?Registrar $rdap, ?Registrar $whois): ?Registrar
    {
        if ($rdap === null) {
            return $whois;
        }
        if ($whois === null) {
            return $rdap;
        }

        return new Registrar(
            name: $rdap->name ?? $whois->name,
            ianaId: $rdap->ianaId ?? $whois->ianaId,
            url: $rdap->url ?? $whois->url,
            abuseEmail: $rdap->abuseEmail ?? $whois->abuseEmail,
            abusePhone: $rdap->abusePhone ?? $whois->abusePhone,
        );
    }

    /**
     * Merge contacts: RDAP contacts take priority per type, WHOIS fills gaps.
     *
     * @param Contact[] $rdap
     * @param Contact[] $whois
     * @return Contact[]
     */
    private function mergeContacts(array $rdap, array $whois): array
    {
        // Index RDAP contacts by type
        $byType = [];
        foreach ($rdap as $contact) {
            $byType[$contact->type->value] = $contact;
        }

        // Add WHOIS contacts only for types not already present from RDAP
        foreach ($whois as $contact) {
            if (!isset($byType[$contact->type->value])) {
                $byType[$contact->type->value] = $contact;
            } else {
                // Merge: fill in nulls from WHOIS into RDAP contact
                $existing = $byType[$contact->type->value];
                $byType[$contact->type->value] = new Contact(
                    type: $existing->type,
                    name: $existing->name ?? $contact->name,
                    organization: $existing->organization ?? $contact->organization,
                    email: $existing->email ?? $contact->email,
                    phone: $existing->phone ?? $contact->phone,
                    fax: $existing->fax ?? $contact->fax,
                    address: $existing->address ?? $contact->address,
                );
            }
        }

        return array_values($byType);
    }

    /**
     * Merge nameserver arrays with deduplication by hostname.
     *
     * @param Nameserver[] $rdap
     * @param Nameserver[] $whois
     * @return Nameserver[]
     */
    private function mergeNameservers(array $rdap, array $whois): array
    {
        $byHost = [];
        foreach ($rdap as $ns) {
            $byHost[strtolower($ns->hostname)] = $ns;
        }

        foreach ($whois as $ns) {
            $key = strtolower($ns->hostname);
            if (!isset($byHost[$key])) {
                $byHost[$key] = $ns;
            } else {
                // Merge IP info from WHOIS if RDAP didn't have it
                $existing = $byHost[$key];
                if ($existing->ipv4 === null && $ns->ipv4 !== null
                    || $existing->ipv6 === null && $ns->ipv6 !== null
                ) {
                    $byHost[$key] = new Nameserver(
                        hostname: $existing->hostname,
                        ipv4: $existing->ipv4 ?? $ns->ipv4,
                        ipv6: $existing->ipv6 ?? $ns->ipv6,
                    );
                }
            }
        }

        return array_values($byHost);
    }

    /**
     * Merge string arrays with deduplication (case-insensitive).
     *
     * @param string[] $a
     * @param string[] $b
     * @return string[]
     */
    private function mergeStringArrays(array $a, array $b): array
    {
        $seen = [];
        $result = [];

        foreach (array_merge($a, $b) as $item) {
            $key = strtolower(trim($item));
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $result[] = $item;
            }
        }

        return $result;
    }
}
