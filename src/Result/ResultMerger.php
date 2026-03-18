<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\Field\Contact;
use Klkvsk\Whoeasy\Result\Info\Field\Nameserver;
use Klkvsk\Whoeasy\Result\Info\Field\Registrar;
use Klkvsk\Whoeasy\Result\Info\IpInfo;

/**
 * Merges AbstractInfo objects of the same type.
 *
 * Strategy: primary source takes priority for scalar fields,
 * secondary fills in gaps. For arrays (contacts, nameservers, status),
 * we deduplicate and combine.
 */
class ResultMerger
{
    /**
     * Merge N info objects via left-fold. Later results fill gaps in earlier ones.
     * Returns null if no results provided.
     */
    public function mergeAll(AbstractInfo ...$results): ?AbstractInfo
    {
        $filtered = array_values(array_filter($results));
        if ($filtered === []) {
            return null;
        }

        return array_reduce(
            array_slice($filtered, 1),
            fn(AbstractInfo $carry, AbstractInfo $item) => $this->merge($carry, $item),
            $filtered[0],
        );
    }

    /**
     * Merge two info objects of the same type. Primary takes priority for scalar fields,
     * arrays are combined with deduplication.
     */
    public function merge(AbstractInfo $primary, AbstractInfo $secondary): AbstractInfo
    {
        if ($primary instanceof DomainInfo && $secondary instanceof DomainInfo) {
            return $this->mergeDomain($primary, $secondary);
        }

        if ($primary instanceof IpInfo && $secondary instanceof IpInfo) {
            return $this->mergeIp($primary, $secondary);
        }

        if ($primary instanceof AsnInfo && $secondary instanceof AsnInfo) {
            return $this->mergeAsn($primary, $secondary);
        }

        // Different types or unknown — primary wins
        return $primary;
    }

    private function mergeDomain(DomainInfo $primary, DomainInfo $secondary): DomainInfo
    {
        return new DomainInfo(
            name: $primary->name ?? $secondary->name,
            registrar: $this->mergeRegistrar($primary->registrar, $secondary->registrar),
            createdDate: $primary->createdDate ?? $secondary->createdDate,
            updatedDate: $primary->updatedDate ?? $secondary->updatedDate,
            expiresDate: $primary->expiresDate ?? $secondary->expiresDate,
            status: $this->mergeStringArrays($primary->status, $secondary->status),
            nameservers: $this->mergeNameservers($primary->nameservers, $secondary->nameservers),
            contacts: $this->mergeContacts($primary->contacts, $secondary->contacts),
            dnssec: $primary->dnssec ?? $secondary->dnssec,
        );
    }

    private function mergeIp(IpInfo $primary, IpInfo $secondary): IpInfo
    {
        return new IpInfo(
            range: $primary->range ?? $secondary->range,
            networkName: $primary->networkName ?? $secondary->networkName,
            description: $primary->description ?? $secondary->description,
            asNumber: $primary->asNumber ?? $secondary->asNumber,
            country: $primary->country ?? $secondary->country,
            createdDate: $primary->createdDate ?? $secondary->createdDate,
            updatedDate: $primary->updatedDate ?? $secondary->updatedDate,
            status: $this->mergeStringArrays($primary->status, $secondary->status),
            contacts: $this->mergeContacts($primary->contacts, $secondary->contacts),
        );
    }

    private function mergeAsn(AsnInfo $primary, AsnInfo $secondary): AsnInfo
    {
        return new AsnInfo(
            asn: $primary->asn ?? $secondary->asn,
            name: $primary->name ?? $secondary->name,
            description: $primary->description ?? $secondary->description,
            country: $primary->country ?? $secondary->country,
            createdDate: $primary->createdDate ?? $secondary->createdDate,
            updatedDate: $primary->updatedDate ?? $secondary->updatedDate,
            status: $this->mergeStringArrays($primary->status, $secondary->status),
            contacts: $this->mergeContacts($primary->contacts, $secondary->contacts),
        );
    }

    private function mergeRegistrar(?Registrar $primary, ?Registrar $secondary): ?Registrar
    {
        if ($primary === null) {
            return $secondary;
        }
        if ($secondary === null) {
            return $primary;
        }

        return new Registrar(
            name: $primary->name ?? $secondary->name,
            ianaId: $primary->ianaId ?? $secondary->ianaId,
            url: $primary->url ?? $secondary->url,
            abuseEmail: $primary->abuseEmail ?? $secondary->abuseEmail,
            abusePhone: $primary->abusePhone ?? $secondary->abusePhone,
        );
    }

    /**
     * Merge contact arrays. Multiple contacts of the same type are preserved.
     * If a contact in B is a subset of a contact in A (same type, all non-null
     * fields in B match A), it's merged into A rather than added as duplicate.
     *
     * @param Contact[] $primary
     * @param Contact[] $secondary
     * @return Contact[]
     */
    private function mergeContacts(array $primary, array $secondary): array
    {
        $result = [...$primary];

        foreach ($secondary as $contact) {
            $merged = false;

            foreach ($result as $i => $existing) {
                if ($existing->type !== $contact->type) {
                    continue;
                }

                // Check if one is a subset of the other (non-null fields match)
                if ($this->contactIsSubset($contact, $existing)) {
                    // B is subset of A — merge B's fields into A (A wins on conflicts)
                    $result[$i] = $this->mergeContact($existing, $contact);
                    $merged = true;
                    break;
                }

                if ($this->contactIsSubset($existing, $contact)) {
                    // A is subset of B — merge A's fields into B (A still wins on conflicts)
                    $result[$i] = $this->mergeContact($existing, $contact);
                    $merged = true;
                    break;
                }
            }

            if (!$merged) {
                $result[] = $contact;
            }
        }

        return $result;
    }

    /**
     * Check if $a's non-null fields are all present and equal in $b.
     */
    private function contactIsSubset(Contact $a, Contact $b): bool
    {
        if ($a->name !== null && $b->name !== null && $a->name !== $b->name) return false;
        if ($a->organization !== null && $b->organization !== null && $a->organization !== $b->organization) return false;
        if ($a->email !== null && $b->email !== null && $a->email !== $b->email) return false;
        if ($a->phone !== null && $b->phone !== null && $a->phone !== $b->phone) return false;
        if ($a->fax !== null && $b->fax !== null && $a->fax !== $b->fax) return false;
        if ($a->address !== null && $b->address !== null && $a->address !== $b->address) return false;
        return true;
    }

    private function mergeContact(Contact $primary, Contact $secondary): Contact
    {
        return new Contact(
            type: $primary->type,
            name: $primary->name ?? $secondary->name,
            organization: $primary->organization ?? $secondary->organization,
            email: $primary->email ?? $secondary->email,
            phone: $primary->phone ?? $secondary->phone,
            fax: $primary->fax ?? $secondary->fax,
            address: $primary->address ?? $secondary->address,
        );
    }

    /**
     * @param Nameserver[] $primary
     * @param Nameserver[] $secondary
     * @return Nameserver[]
     */
    private function mergeNameservers(array $primary, array $secondary): array
    {
        $byHost = [];
        foreach ($primary as $ns) {
            $byHost[strtolower($ns->hostname)] = $ns;
        }

        foreach ($secondary as $ns) {
            $key = strtolower($ns->hostname);
            if (!isset($byHost[$key])) {
                $byHost[$key] = $ns;
            } else {
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
